use std::collections::HashMap;
use std::fmt::Display;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, OnceLock, RwLock};

use tracing::warn;

const EN_US: &str = include_str!("i18n/en_us.json");
const FALLBACK_LOCALE: &str = "en_us";

type Table = HashMap<String, String>;

static BUILTIN: LazyLock<Table> = LazyLock::new(|| serde_json::from_str(EN_US).unwrap_or_default());
static TRANSLATIONS: OnceLock<Translations> = OnceLock::new();

struct Translations {
    dir: PathBuf,
    default_locale: String,
    locales: RwLock<HashMap<String, Table>>,
}

/// Loads every `<locale>.json` in `dir`, writing the English file first if it is missing.
/// Files in subfolders belong to the plugin named after the folder.
pub fn init(dir: &Path, default_locale: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    write_if_missing(&dir.join(format!("{FALLBACK_LOCALE}.json")), EN_US)?;
    let translations = Translations {
        dir: dir.to_path_buf(),
        default_locale: normalize(default_locale),
        locales: RwLock::new(HashMap::new()),
    };
    translations.load_dir(dir, None)?;
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        if path.is_dir()
            && let Some(namespace) = path.file_name().and_then(|n| n.to_str())
        {
            translations.load_dir(&path, Some(namespace))?;
        }
    }
    let _ = TRANSLATIONS.set(translations);
    Ok(())
}

impl Translations {
    fn load_dir(&self, dir: &Path, namespace: Option<&str>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(locale) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if let Some(table) = load_file(&path, namespace) {
                self.insert(locale, table);
            }
        }
        Ok(())
    }

    fn insert(&self, locale: &str, table: Table) {
        if let Ok(mut locales) = self.locales.write() {
            locales.entry(normalize(locale)).or_default().extend(table);
        }
    }

    fn lookup(&self, locale: Option<&str>, key: &str) -> Option<String> {
        let locales = self.locales.read().ok()?;
        let find = |locale: &str| locales.get(locale).and_then(|t| t.get(key)).cloned();
        if let Some(locale) = locale.map(normalize) {
            if let Some(text) = find(&locale) {
                return Some(text);
            }
            let language = locale.split('_').next().unwrap_or_default();
            let mut related: Vec<&String> = locales
                .keys()
                .filter(|l| l.split('_').next() == Some(language))
                .collect();
            related.sort();
            if let Some(text) = related.into_iter().find_map(|l| find(l)) {
                return Some(text);
            }
        }
        find(&self.default_locale).or_else(|| find(FALLBACK_LOCALE))
    }
}

/// Returns the text for `key` in `locale`, falling back to the default language and then English.
pub fn translate(locale: Option<&str>, key: &str, args: &[&(dyn Display + Sync)]) -> String {
    let template = TRANSLATIONS
        .get()
        .and_then(|t| t.lookup(locale, key))
        .or_else(|| BUILTIN.get(key).cloned())
        .unwrap_or_else(|| key.to_string());
    format_template(&template, args)
}

/// Fills `%s` and `%1$s` placeholders; `%%` is a literal percent sign.
fn format_template(template: &str, args: &[&(dyn Display + Sync)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut next = 0;
    let mut rest = template;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        if let Some(after) = tail.strip_prefix('%') {
            out.push('%');
            rest = after;
            continue;
        }
        if let Some(after) = tail.strip_prefix('s') {
            if let Some(arg) = args.get(next) {
                out.push_str(&arg.to_string());
            }
            next += 1;
            rest = after;
            continue;
        }
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0
            && let Some(after) = tail[digits..].strip_prefix("$s")
        {
            let index = tail[..digits].parse::<usize>().unwrap_or(0);
            if let Some(arg) = index.checked_sub(1).and_then(|i| args.get(i)) {
                out.push_str(&arg.to_string());
            }
            rest = after;
            continue;
        }
        out.push('%');
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// Registers a plugin's default texts, writing them to `lang/<namespace>/<locale>.json` if that file
/// is missing. Texts in the file win over the defaults.
pub fn register(
    namespace: &str,
    locale: &str,
    entries: Vec<(String, String)>,
) -> std::io::Result<()> {
    let valid = |name: &str| {
        !name.is_empty()
            && !name.starts_with('.')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    };
    let locale = normalize(locale);
    if !valid(namespace) || !valid(&locale) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid plugin name or locale '{namespace}/{locale}'"),
        ));
    }
    let Some(translations) = TRANSLATIONS.get() else {
        return Ok(());
    };
    let dir = translations.dir.join(namespace);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{locale}.json"));
    let defaults: std::collections::BTreeMap<String, String> = entries.into_iter().collect();
    let json = serde_json::to_string_pretty(&defaults).map_err(std::io::Error::other)?;
    write_if_missing(&path, &json)?;

    let mut table: Table = defaults
        .into_iter()
        .map(|(key, text)| (format!("{namespace}:{key}"), text))
        .collect();
    table.extend(load_file(&path, Some(namespace)).unwrap_or_default());
    translations.insert(&locale, table);
    Ok(())
}

fn load_file(path: &Path, namespace: Option<&str>) -> Option<Table> {
    let table: Table = match std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
    {
        Ok(table) => table,
        Err(e) => {
            warn!("Skipping translation file '{}': {}", path.display(), e);
            return None;
        }
    };
    Some(
        table
            .into_iter()
            .map(|(key, text)| match namespace {
                Some(namespace) => (format!("{namespace}:{key}"), text),
                None => (key, text),
            })
            .collect(),
    )
}

fn normalize(locale: &str) -> String {
    locale.trim().to_ascii_lowercase().replace('-', "_")
}

fn write_if_missing(path: &Path, contents: &str) -> std::io::Result<()> {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => file.write_all(contents.as_bytes()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_template() {
        assert_eq!(
            format_template("%s went to %s", &[&"Alex", &"lobby"]),
            "Alex went to lobby"
        );
        assert_eq!(format_template("%2$s <- %1$s", &[&"a", &"b"]), "b <- a");
        assert_eq!(format_template("100%% %s %", &[&1]), "100% 1 %");
        assert_eq!(format_template("%s %s", &[&"only"]), "only ");
    }

    #[test]
    fn test_lookup_falls_back_by_language() {
        let translations = Translations {
            dir: PathBuf::new(),
            default_locale: "de_de".to_string(),
            locales: RwLock::new(HashMap::from([
                (
                    "pt_pt".to_string(),
                    Table::from([("k".to_string(), "pt".to_string())]),
                ),
                (
                    "de_de".to_string(),
                    Table::from([("k".to_string(), "de".to_string())]),
                ),
                (
                    "en_us".to_string(),
                    Table::from([("only_en".to_string(), "en".to_string())]),
                ),
            ])),
        };
        assert_eq!(
            translations.lookup(Some("PT-BR"), "k").as_deref(),
            Some("pt")
        );
        assert_eq!(
            translations.lookup(Some("tr_tr"), "k").as_deref(),
            Some("de")
        );
        assert_eq!(translations.lookup(None, "only_en").as_deref(), Some("en"));
        assert_eq!(translations.lookup(None, "missing"), None);
    }
}
