use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use base64::prelude::*;
use tracing::{debug, info, warn};

pub const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

#[derive(Clone, Debug)]
pub struct StatusIcon {
    pub data_uri: Arc<str>,
    pub last_modified: Option<SystemTime>,
}

impl StatusIcon {
    /// Loads, validates, and encodes a PNG file into a Minecraft status favicon data URI
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let bytes = fs::read(path)
            .map_err(|e| format!("Failed to read icon file '{}': {}", path.display(), e))?;
        Self::from_bytes(bytes, path.to_path_buf())
    }

    /// Validates PNG bytes and builds a StatusIcon
    pub fn from_bytes(bytes: Vec<u8>, path: PathBuf) -> Result<Self, String> {
        if bytes.len() < 24 {
            return Err(format!(
                "Icon file '{}' is too small ({} bytes)",
                path.display(),
                bytes.len()
            ));
        }

        if bytes[..8] != PNG_SIGNATURE {
            return Err(format!(
                "Icon file '{}' does not have a valid PNG signature (expected PNG format)",
                path.display()
            ));
        }

        let chunk_type = &bytes[12..16];
        if chunk_type != b"IHDR" {
            return Err(format!(
                "Icon file '{}' is missing valid IHDR chunk",
                path.display()
            ));
        }

        let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);

        if width != 64 || height != 64 {
            warn!(
                "Status icon '{}' dimensions are {}x{} pixels. Minecraft requires exactly 64x64 PNG images for server list icons.",
                path.display(),
                width,
                height
            );
        }

        let b64 = BASE64_STANDARD.encode(&bytes);
        let data_uri: Arc<str> = format!("data:image/png;base64,{}", b64).into();

        let last_modified = fs::metadata(&path).and_then(|m| m.modified()).ok();

        info!(
            "Loaded status icon from '{}' ({}x{} pixels, {} bytes base64)",
            path.display(),
            width,
            height,
            data_uri.len()
        );

        Ok(Self {
            data_uri,
            last_modified,
        })
    }
}

/// Manages status images for the proxy, supporting global icons, per-server icons,
/// and automatic hot-reloading when image files on disk change.
pub struct StatusIconManager {
    default_icon_path: Option<PathBuf>,
    server_icons: HashMap<String, PathBuf>,
    forced_hosts: HashMap<String, String>,
    default_server: String,
    cache: RwLock<HashMap<PathBuf, StatusIcon>>,
}

impl StatusIconManager {
    pub fn new(
        configured_default_path: Option<String>,
        server_icons: HashMap<String, String>,
        forced_hosts: HashMap<String, String>,
        default_server: String,
    ) -> Self {
        let default_icon_path = match configured_default_path {
            Some(p) if !p.trim().is_empty() => Some(PathBuf::from(p)),
            _ => None,
        };

        let server_icon_paths: HashMap<String, PathBuf> = server_icons
            .into_iter()
            .map(|(k, v)| (k, PathBuf::from(v)))
            .collect();

        let manager = Self {
            default_icon_path,
            server_icons: server_icon_paths,
            forced_hosts,
            default_server,
            cache: RwLock::new(HashMap::new()),
        };

        manager.preload_all();
        manager
    }

    fn preload_all(&self) {
        if let Some(path) = &self.default_icon_path {
            self.load_or_reload(path);
        }
        for path in self.server_icons.values() {
            self.load_or_reload(path);
        }
    }

    /// Looks up and returns the cached base64 data URI for the given virtual host or default
    pub fn get_icon_for_host(&self, host: Option<&str>) -> Option<Arc<str>> {
        let target_path = self.resolve_icon_path(host)?;
        self.load_or_reload(&target_path)
    }

    /// Resolves which icon path applies based on the virtual host or default
    fn resolve_icon_path(&self, host: Option<&str>) -> Option<PathBuf> {
        if let Some(h) = host {
            let normalized = crate::config::normalize_host(h);
            let clean_host = normalized.as_str();

            if let Some(target_server) = self.forced_hosts.get(clean_host)
                && let Some(path) = self.server_icons.get(target_server)
            {
                return Some(path.clone());
            }

            if let Some(path) = self.server_icons.get(clean_host) {
                return Some(path.clone());
            }
        }

        if let Some(path) = self.server_icons.get(&self.default_server) {
            return Some(path.clone());
        }

        self.default_icon_path.clone()
    }

    /// Retrieves cached icon or reloads from disk if file was modified
    fn load_or_reload(&self, path: &Path) -> Option<Arc<str>> {
        if let Ok(cache) = self.cache.read()
            && let Some(cached) = cache.get(path)
        {
            if let Ok(meta) = fs::metadata(path) {
                if let Ok(mtime) = meta.modified()
                    && cached.last_modified == Some(mtime)
                {
                    return Some(cached.data_uri.clone());
                }
            } else {
                return Some(cached.data_uri.clone());
            }
        }

        match StatusIcon::load_from_file(path) {
            Ok(icon) => {
                let uri = icon.data_uri.clone();
                if let Ok(mut cache) = self.cache.write() {
                    cache.insert(path.to_path_buf(), icon);
                }
                Some(uri)
            }
            Err(e) => {
                debug!("Could not load status icon '{}': {}", path.display(), e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_png(w: u32, h: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PNG_SIGNATURE);
        bytes.extend_from_slice(&13u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&w.to_be_bytes());
        bytes.extend_from_slice(&h.to_be_bytes());
        bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes
    }

    #[test]
    fn test_valid_png_parsing() {
        let png = create_test_png(64, 64);
        let icon = StatusIcon::from_bytes(png, PathBuf::from("test.png")).unwrap();
        assert!(icon.data_uri.starts_with("data:image/png;base64,"));
    }

    #[test]
    fn test_invalid_signature() {
        let bad_bytes = vec![0u8; 32];
        let res = StatusIcon::from_bytes(bad_bytes, PathBuf::from("test.png"));
        assert!(res.is_err());
    }

    #[test]
    fn test_icon_manager_resolution() {
        let mut server_icons = HashMap::new();
        server_icons.insert("survival".to_string(), "survival.png".to_string());
        let mut forced_hosts = HashMap::new();
        forced_hosts.insert("mc.survival.com".to_string(), "survival".to_string());

        let manager = StatusIconManager::new(
            Some("default.png".to_string()),
            server_icons,
            forced_hosts,
            "lobby".to_string(),
        );

        let path = manager.resolve_icon_path(Some("mc.survival.com")).unwrap();
        assert_eq!(path, PathBuf::from("survival.png"));

        let def_path = manager.resolve_icon_path(Some("other.com")).unwrap();
        assert_eq!(def_path, PathBuf::from("default.png"));
    }

    #[test]
    fn test_icon_manager_default_none() {
        let manager =
            StatusIconManager::new(None, HashMap::new(), HashMap::new(), "lobby".to_string());

        assert!(manager.resolve_icon_path(None).is_none());
        assert!(
            manager
                .resolve_icon_path(Some("play.example.com"))
                .is_none()
        );
        assert!(manager.get_icon_for_host(None).is_none());
    }
}
