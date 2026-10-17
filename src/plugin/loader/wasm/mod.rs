pub mod wasm_host;

use std::path::Path;
use std::sync::Arc;

use crate::plugin::api::PluginMetadata;
use wasm_host::state::ProxyPluginContext;
pub use wasm_host::{PluginLimits, PluginRuntime, WasmPlugin};

pub struct WasmPluginLoader {
    runtime: PluginRuntime,
}

impl WasmPluginLoader {
    pub fn new(limits: PluginLimits) -> Result<Self, wasm_host::PluginInitError> {
        let runtime = PluginRuntime::new(limits)?;
        Ok(Self { runtime })
    }

    pub fn can_load(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("wasm"))
            .unwrap_or(false)
    }

    pub async fn load(
        &self,
        path: &Path,
        proxy: Option<ProxyPluginContext>,
    ) -> Result<(Arc<WasmPlugin>, PluginMetadata), wasm_host::PluginInitError> {
        self.runtime.init_plugin(path, proxy).await
    }
}
