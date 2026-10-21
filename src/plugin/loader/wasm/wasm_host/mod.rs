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
use tokio::sync::{Notify, oneshot};
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Engine, Store, UpdateDeadline};

use crate::plugin::api::{PluginContext, PluginMetadata};
use concurrent_store::{LegacyStore, LegacySyncReentry, TokioSpawner};
use state::{PluginHostState, PluginLimiter, ProxyPluginContext};

/// The folder a plugin file gets as /data. It is kept next to the plugin files, so it follows
/// plugins.plugin_dir, and its name is cleaned up so a file like "...wasm" cannot point it at
/// ".." or ".".
pub fn data_folder(path: &Path) -> PathBuf {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    path.parent()
        .unwrap_or(Path::new("."))
        .join("data")
        .join(crate::i18n::namespace(&stem))
}

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
    kill_signal: Arc<Notify>,
    early_translations: std::sync::Mutex<Vec<(String, state::Translations)>>,
    // Set once the plugin is being stopped, so calls that fail because of it are not crashes
    stopping: AtomicBool,
    call_timeout: Duration,
    monitor: std::sync::OnceLock<tokio::sync::mpsc::Sender<MonitorJob>>,
    monitor_behind: AtomicBool,
}

// Monitor handlers cannot change an event, so they see it once it is decided, in order, without
// holding up the packet it came from. Each plugin has its own queue, so a slow one only delays
// itself; events beyond this many waiting are not shown to it.
const MONITOR_QUEUE: usize = 1024;

struct MonitorJob {
    handler_ids: Vec<u32>,
    event: wit::vine::plugin::event::Event,
    name: &'static str,
}

/// Handed to a guest call, which begins it once the guest is about to run and keeps what it
/// returns until the guest is done
struct CallStart {
    started: oneshot::Sender<()>,
    running: oneshot::Sender<()>,
}

impl CallStart {
    fn begin(self) -> oneshot::Sender<()> {
        let _ = self.started.send(());
        self.running
    }
}

impl WasmPlugin {
    pub fn is_disabled(&self) -> bool {
        self.killed.load(Ordering::Relaxed)
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    /// Registers the translations from init-plugin, once the plugin is accepted under its name
    pub fn register_early_translations(&self) {
        let early = self
            .early_translations
            .lock()
            .map(|mut early| std::mem::take(&mut *early))
            .unwrap_or_default();
        for (locale, entries) in early {
            state::register_translations(&self.metadata.name, locale, entries);
        }
    }

    /// Stops the plugin, letting calls already running finish within the call timeout. A call
    /// still running after that is interrupted and the plugin is disabled.
    pub async fn shutdown(&self) {
        self.stopping.store(true, Ordering::Release);
        if tokio::time::timeout(
            self.call_timeout,
            self.store.shutdown(|_| Box::pin(async { Ok(()) })),
        )
        .await
        .is_err()
        {
            if !self.is_disabled() {
                tracing::warn!(
                    "Plugin '{}' did not stop within {:?} and has been disabled",
                    self.metadata.name,
                    self.call_timeout
                );
            }
            self.kill();
        }
    }

    fn kill(&self) {
        self.killed.store(true, Ordering::Relaxed);
        self.kill_signal.notify_waiters();
    }

    /// Runs a guest call, timing it from when the guest starts rather than while it waits for
    /// other plugins to finish. The guest is timed even if the caller stops waiting, and calls
    /// still queued behind it fail once it is disabled.
    async fn guarded<R, F>(&self, call: impl FnOnce(CallStart) -> F) -> wasmtime::Result<R>
    where
        F: Future<Output = wasmtime::Result<R>>,
    {
        let disabled = self.kill_signal.notified();
        tokio::pin!(disabled);
        disabled.as_mut().enable();
        if self.killed.load(Ordering::Relaxed) {
            return Err(wasmtime::Error::msg(
                "plugin is disabled; reload it to start it again",
            ));
        }
        let (started, admitted) = oneshot::channel();
        let (running, finished) = oneshot::channel();
        let call = call(CallStart { started, running });

        let killed = self.killed.clone();
        let kill_signal = self.kill_signal.clone();
        let name = self.metadata.name.clone();
        let limit = self.call_timeout;
        tokio::spawn(async move {
            if admitted.await.is_err() {
                return;
            }
            if tokio::time::timeout(limit, finished).await.is_err() {
                killed.store(true, Ordering::Relaxed);
                kill_signal.notify_waiters();
                tracing::error!(
                    "Plugin '{}' took longer than {:?} and has been disabled",
                    name,
                    limit
                );
            }
        });

        tokio::select! {
            result = call => {
                // A trap leaves the store unusable, so the plugin is marked as such
                if let Err(e) = &result
                    && !self.is_stopping()
                {
                    self.kill();
                    tracing::error!(
                        "Plugin '{}' crashed and has been disabled: {}",
                        self.metadata.name,
                        e
                    );
                }
                result
            }
            () = disabled => Err(wasmtime::Error::msg("plugin has been disabled")),
        }
    }

    pub async fn on_load(&self, context: Arc<PluginContext>) -> Result<(), String> {
        let func = self.instance.func_on_load();
        let context_clone = context.clone();
        self.guarded(|started| {
            self.store.call_guest(move |mut guest| {
                Box::pin(async move {
                    let _running = started.begin();
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
                    let _running = started.begin();
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
                    let _running = started.begin();
                    let (res,) = guest.call(func, (handler_id, event)).await?;
                    Ok(res)
                })
            })
        })
        .await
    }

    /// Shows a decided event to this plugin's Monitor handlers on a task of its own
    pub fn watch(
        self: &Arc<Self>,
        handler_ids: Vec<u32>,
        event: wit::vine::plugin::event::Event,
        name: &'static str,
    ) {
        let monitor = self.monitor.get_or_init(|| {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<MonitorJob>(MONITOR_QUEUE);
            // Holding the plugin weakly lets the task end once the plugin is gone
            let plugin = Arc::downgrade(self);
            tokio::spawn(async move {
                while let Some(job) = rx.recv().await {
                    let Some(plugin) = plugin.upgrade() else {
                        break;
                    };
                    // Skipped rather than ended, so events keep being taken off the queue
                    if plugin.is_stopping() || plugin.is_disabled() {
                        continue;
                    }
                    for handler_id in job.handler_ids {
                        if let Err(e) = plugin.handle_event(handler_id, job.event.clone()).await {
                            tracing::error!(
                                "Error in plugin '{}' handling {}: {}",
                                plugin.metadata.name,
                                job.name,
                                e
                            );
                        }
                    }
                }
            });
            tx
        });
        let job = MonitorJob {
            handler_ids,
            event,
            name,
        };
        if monitor.try_send(job).is_ok() {
            self.monitor_behind.store(false, Ordering::Relaxed);
        } else if !self.monitor_behind.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "Plugin '{}' is falling behind on Monitor events; some {} events skip it",
                self.metadata.name,
                name
            );
        }
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
                    let _running = started.begin();
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
                    let _running = started.begin();
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
        let spawner = Arc::new(TokioSpawner::new(tokio::runtime::Handle::current()));

        Ok(Self {
            engine,
            linker,
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
        // Each plugin gets its own gate: no host call runs another plugin, so they never need to
        // take turns, and a slow or stuck plugin cannot hold up the others
        let reentry = LegacySyncReentry::new();

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
        let data_folder = data_folder(path);
        let _ = fs::create_dir_all(&data_folder);

        let mut state = PluginHostState::new(filename, data_folder, proxy);
        state.limits = PluginLimiter::new(self.limits.max_memory_bytes);
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
            reentry.scope_bootstrap(plugin_pre.instantiate_async(&mut store)),
        )
        .await
        .map_err(|_| PluginInitError::InitTimedOut(timeout))?
        .map_err(PluginInitError::InstantiationFailed)?;

        tokio::time::timeout(
            timeout,
            store.run_concurrent(async |accessor| {
                reentry
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
                reentry
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
        let early_translations = store.data_mut().take_early_translations();

        let legacy_store = concurrent_store::start_legacy_store(
            store,
            reentry,
            Arc::clone(&self.spawner) as Arc<dyn pumpkin_plugin_runtime::RuntimeSpawner>,
        )
        .await
        .map_err(PluginInitError::InstantiationFailed)?;

        let wasm_plugin = Arc::new(WasmPlugin {
            instance: plugin,
            store: legacy_store,
            metadata: metadata.clone(),
            killed,
            kill_signal: Arc::new(Notify::new()),
            early_translations: std::sync::Mutex::new(early_translations),
            stopping: AtomicBool::new(false),
            call_timeout: timeout,
            monitor: std::sync::OnceLock::new(),
            monitor_behind: AtomicBool::new(false),
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
