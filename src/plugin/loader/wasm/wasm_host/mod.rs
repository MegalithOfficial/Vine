pub mod concurrent_store;
pub mod state;
pub mod wit;

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::oneshot;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Engine, Store, UpdateDeadline};

use crate::plugin::api::{PluginContext, PluginMetadata};
use concurrent_store::{LegacyStore, LegacySyncReentry, TokioSpawner};
use state::{PluginHostState, ProxyPluginContext};

#[derive(Error, Debug)]
pub enum PluginInitError {
    #[error("Failed to read plugin file '{0}': {1}")]
    FileReadFailed(PathBuf, std::io::Error),
    #[error("Failed to compile WebAssembly component: {0}")]
    ComponentCompilationFailed(wasmtime::Error),
    #[error("Failed to setup linker: {0}")]
    LinkerSetupFailed(wasmtime::Error),
    #[error("Failed to instantiate plugin: {0}")]
    InstantiationFailed(wasmtime::Error),
    #[error("Failed to initialize plugin: {0}")]
    InitPluginFailed(wasmtime::Error),
    #[error("Failed to retrieve metadata: {0}")]
    GetMetadataFailed(wasmtime::Error),
    #[error("Engine creation failed: {0}")]
    EngineCreationFailed(wasmtime::Error),
    #[error("Plugin did not finish initializing within {0:?}")]
    InitTimedOut(Duration),
}

const EPOCH_TICK: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug)]
pub struct PluginLimits {
    pub max_memory_bytes: usize,
    pub call_timeout: Duration,
}

impl From<&crate::config::PluginConfig> for PluginLimits {
    fn from(config: &crate::config::PluginConfig) -> Self {
        Self {
            max_memory_bytes: usize::try_from(config.max_memory_mb.saturating_mul(1024 * 1024))
                .unwrap_or(usize::MAX),
            call_timeout: Duration::from_millis(config.call_timeout_ms),
        }
    }
}

pub fn setup_linker(engine: &Engine) -> wasmtime::Result<Linker<PluginHostState>> {
    let mut linker = Linker::<PluginHostState>::new(engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wit::Plugin::add_to_linker::<_, HasSelf<_>>(&mut linker, |state: &mut PluginHostState| state)?;
    Ok(linker)
}

pub struct WasmPlugin {
    pub instance: wit::Plugin,
    pub store: LegacyStore,
    pub metadata: PluginMetadata,
    killed: Arc<AtomicBool>,
    call_timeout: Duration,
}

impl WasmPlugin {
    pub fn is_disabled(&self) -> bool {
        self.killed.load(Ordering::Relaxed)
    }

    pub async fn shutdown(&self) {
        let _ = tokio::time::timeout(
            self.call_timeout,
            self.store.shutdown(|_| Box::pin(async { Ok(()) })),
        )
        .await;
    }

    /// Runs a guest call, timing it from when the guest starts rather than while it waits for
    /// other plugins to finish. The call signals its start through the given sender.
    async fn guarded<R, F>(
        &self,
        call: impl FnOnce(oneshot::Sender<()>) -> F,
    ) -> wasmtime::Result<R>
    where
        F: Future<Output = wasmtime::Result<R>>,
    {
        if self.killed.load(Ordering::Relaxed) {
            return Err(wasmtime::Error::msg(
                "plugin was disabled after exceeding its time limit",
            ));
        }
        let (started, admitted) = oneshot::channel();
        let call = call(started);
        let limit = async {
            match admitted.await {
                Ok(()) => tokio::time::sleep(self.call_timeout).await,
                Err(_) => std::future::pending().await,
            }
        };
        tokio::select! {
            result = call => result,
            () = limit => {
                self.killed.store(true, Ordering::Relaxed);
                tracing::error!(
                    "Plugin '{}' took longer than {:?} and has been disabled",
                    self.metadata.name,
                    self.call_timeout
                );
                Err(wasmtime::Error::msg("plugin call timed out"))
            }
        }
    }

    pub async fn on_load(&self, context: Arc<PluginContext>) -> Result<(), String> {
        let func = self.instance.func_on_load();
        let context_clone = context.clone();
        self.guarded(|started| {
            self.store.call_guest(move |mut guest| {
                Box::pin(async move {
                    let _ = started.send(());
                    let context_res =
                        guest.with(|mut store| store.data_mut().add_context(context_clone))?;
                    let (res,) = guest.call(func, (context_res,)).await?;
                    Ok(res)
                })
            })
        })
        .await
        .map_err(|e| e.to_string())?
    }

    pub async fn on_unload(&self, context: Arc<PluginContext>) -> Result<(), String> {
        let func = self.instance.func_on_unload();
        let context_clone = context.clone();
        self.guarded(|started| {
            self.store.call_guest(move |mut guest| {
                Box::pin(async move {
                    let _ = started.send(());
                    let context_res =
                        guest.with(|mut store| store.data_mut().add_context(context_clone))?;
                    let (res,) = guest.call(func, (context_res,)).await?;
                    Ok(res)
                })
            })
        })
        .await
        .map_err(|e| e.to_string())?
    }

    pub async fn handle_event(
        &self,
        handler_id: u32,
        event: wit::vine::plugin::event::Event,
    ) -> Result<wit::vine::plugin::event::Event, wasmtime::Error> {
        let func = self.instance.func_handle_event();
        self.guarded(|started| {
            self.store.call_guest(move |mut guest| {
                Box::pin(async move {
                    let _ = started.send(());
                    let (res,) = guest.call(func, (handler_id, event)).await?;
                    Ok(res)
                })
            })
        })
        .await
    }

    pub async fn handle_command(
        &self,
        command_id: u32,
        sender: wit::vine::plugin::types::CommandSender,
        args: Vec<String>,
    ) -> Result<Result<i32, String>, wasmtime::Error> {
        let func = self.instance.func_handle_command();
        self.guarded(|started| {
            self.store.call_guest(move |mut guest| {
                Box::pin(async move {
                    let _ = started.send(());
                    let (res,) = guest.call(func, (command_id, sender, args)).await?;
                    Ok(res)
                })
            })
        })
        .await
    }

    pub async fn handle_command_suggestion(
        &self,
        command_id: u32,
        sender: wit::vine::plugin::types::CommandSender,
        args: Vec<String>,
    ) -> Result<Vec<String>, wasmtime::Error> {
        let func = self.instance.func_handle_command_suggestion();
        self.guarded(|started| {
            self.store.call_guest(move |mut guest| {
                Box::pin(async move {
                    let _ = started.send(());
                    let (res,) = guest.call(func, (command_id, sender, args)).await?;
                    Ok(res)
                })
            })
        })
        .await
    }
}

pub struct PluginRuntime {
    engine: Engine,
    linker: Linker<PluginHostState>,
    reentry: LegacySyncReentry,
    spawner: Arc<TokioSpawner>,
    limits: PluginLimits,
}

impl PluginRuntime {
    pub fn new(limits: PluginLimits) -> Result<Self, PluginInitError> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        config.wasm_component_model_async(true);
        config.concurrency_support(true);
        config.epoch_interruption(true);

        let engine = Engine::new(&config).map_err(PluginInitError::EngineCreationFailed)?;
        // A plain thread, since a runaway plugin may be what is starving the async runtime
        let ticker = engine.weak();
        std::thread::Builder::new()
            .name("plugin-epoch".to_string())
            .spawn(move || {
                while let Some(engine) = ticker.upgrade() {
                    engine.increment_epoch();
                    drop(engine);
                    std::thread::sleep(EPOCH_TICK);
                }
            })
            .map_err(|e| PluginInitError::EngineCreationFailed(wasmtime::Error::msg(e)))?;
        let linker = setup_linker(&engine).map_err(PluginInitError::LinkerSetupFailed)?;
        let reentry = LegacySyncReentry::new();
        let spawner = Arc::new(TokioSpawner::new(tokio::runtime::Handle::current()));

        Ok(Self {
            engine,
            linker,
            reentry,
            spawner,
            limits,
        })
    }

    pub async fn init_plugin(
        &self,
        path: &Path,
        proxy: Option<ProxyPluginContext>,
    ) -> Result<(Arc<WasmPlugin>, PluginMetadata), PluginInitError> {
        let wasm_bytes =
            fs::read(path).map_err(|e| PluginInitError::FileReadFailed(path.to_path_buf(), e))?;

        let component = Component::new(&self.engine, &wasm_bytes)
            .map_err(PluginInitError::ComponentCompilationFailed)?;

        let instance_pre = self
            .linker
            .instantiate_pre(&component)
            .map_err(PluginInitError::InstantiationFailed)?;

        let plugin_pre =
            wit::PluginPre::new(instance_pre).map_err(PluginInitError::InstantiationFailed)?;

        let filename = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let data_folder = PathBuf::from("plugins").join("data").join(&filename);
        let _ = fs::create_dir_all(&data_folder);

        let mut state = PluginHostState::new(filename, data_folder, proxy);
        state.limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(self.limits.max_memory_bytes)
            .build();
        let killed = state.killed.clone();
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(|store| {
            Ok(if store.data().killed.load(Ordering::Relaxed) {
                UpdateDeadline::Interrupt
            } else {
                UpdateDeadline::Yield(1)
            })
        });
        let timeout = self.limits.call_timeout;

        let plugin = tokio::time::timeout(
            timeout,
            self.reentry
                .scope_bootstrap(plugin_pre.instantiate_async(&mut store)),
        )
        .await
        .map_err(|_| PluginInitError::InitTimedOut(timeout))?
        .map_err(PluginInitError::InstantiationFailed)?;

        tokio::time::timeout(
            timeout,
            store.run_concurrent(async |accessor| {
                self.reentry
                    .scope_bootstrap(plugin.call_init_plugin(accessor))
                    .await
            }),
        )
        .await
        .map_err(|_| PluginInitError::InitTimedOut(timeout))?
        .map_err(PluginInitError::InitPluginFailed)?
        .map_err(PluginInitError::InitPluginFailed)?;

        let raw_meta = tokio::time::timeout(
            timeout,
            store.run_concurrent(async |accessor| {
                self.reentry
                    .scope_bootstrap(plugin.call_get_metadata(accessor))
                    .await
            }),
        )
        .await
        .map_err(|_| PluginInitError::InitTimedOut(timeout))?
        .map_err(PluginInitError::GetMetadataFailed)?
        .map_err(PluginInitError::GetMetadataFailed)?;

        let metadata = PluginMetadata {
            name: raw_meta.name.clone(),
            version: raw_meta.version,
            authors: raw_meta.authors,
            description: raw_meta.description,
            dependencies: raw_meta.dependencies,
        };

        store.data_mut().plugin_name = raw_meta.name;

        let legacy_store = concurrent_store::start_legacy_store(
            store,
            self.reentry.clone(),
            Arc::clone(&self.spawner) as Arc<dyn pumpkin_plugin_runtime::RuntimeSpawner>,
        )
        .await
        .map_err(PluginInitError::InstantiationFailed)?;

        let wasm_plugin = Arc::new(WasmPlugin {
            instance: plugin,
            store: legacy_store,
            metadata: metadata.clone(),
            killed,
            call_timeout: timeout,
        });

        let weak = Arc::downgrade(&wasm_plugin);
        wasm_plugin
            .store
            .call(move |accessor| {
                Box::pin(async move {
                    accessor.with(|mut store| {
                        store.data_mut().plugin = Some(weak);
                    });
                    Ok(())
                })
            })
            .await
            .map_err(PluginInitError::InstantiationFailed)?;

        Ok((wasm_plugin, metadata))
    }
}
