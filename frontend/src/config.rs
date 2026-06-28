//! Editable settings, persisted to the repo's committed default config files.
//!
//! The default state is derived from the [`model`](crate::model) catalog: each
//! ecosystem starts with its default registry endpoint and every capability it
//! supports enabled (the engine runs all applicable detectors by default).
//!
//! This app manages the **repo defaults** — the committed
//! `config/defaults/<slug>.json` files the Go engine embeds at build time. Each
//! file is in the [`EcosystemFile`] shape, identical to the Go
//! `config.EcosystemConfig`. Operators may additionally drop *override* files in
//! their system config dir (`MALSCAN_CONFIG_DIR` / `$XDG_CONFIG_HOME`), which the
//! engine overlays on the defaults at runtime; the frontend does not touch those.
//!
//! The defaults directory is [`defaults_dir`]: `MALSCAN_DEFAULTS_DIR` if set,
//! else `<repo>/config/defaults` (resolved relative to this crate). The app loads
//! it on startup ([`AppConfig::load`]) and rewrites a file on save
//! ([`write_ecosystem`]).
//!
//! Serialisation uses a `BTreeMap` so JSON key order is stable.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model;

/// Per-ecosystem settings (in memory; the slug is the [`AppConfig`] map key).
#[derive(Clone, Serialize, Deserialize)]
pub struct EcosystemConfig {
    /// Registry API endpoint (editable; persisted to disk).
    pub registry_endpoint: String,
    /// Capability key → enabled. Only keys the ecosystem supports are present.
    pub capabilities: BTreeMap<String, bool>,
}

impl EcosystemConfig {
    /// Default config for `slug`: default endpoint, all supported caps on.
    fn defaults_for(slug: &str) -> Self {
        let registry_endpoint = model::ecosystem(slug)
            .map(|e| e.default_endpoint.to_string())
            .unwrap_or_default();
        let capabilities = model::capabilities_for(slug)
            .into_iter()
            .map(|c| (c.key.to_string(), true))
            .collect();
        Self {
            registry_endpoint,
            capabilities,
        }
    }

    /// Count of enabled capabilities.
    pub fn enabled_count(&self) -> usize {
        self.capabilities.values().filter(|v| **v).count()
    }
}

/// On-disk shape of one ecosystem's config (`<config-dir>/<slug>.json`). Mirrors
/// the Go `config.EcosystemConfig` field-for-field so the engine reads what the
/// UI writes.
#[derive(Serialize, Deserialize)]
struct EcosystemFile {
    ecosystem: String,
    registry_endpoint: String,
    capabilities: BTreeMap<String, bool>,
}

/// On-disk shape of `badnet/data/feeds.json`. This is consumed by the Go
/// `badnet` package at runtime to map each source URL to its parser.
#[derive(Serialize)]
struct FeedSourcesFile {
    schema_version: String,
    feeds: Vec<FeedSourceFile>,
}

#[derive(Serialize)]
struct FeedSourceFile {
    key: String,
    name: String,
    url: String,
    parser: String,
    detail: String,
    enabled: bool,
}

/// The whole app's settings: one entry per ecosystem, keyed by slug.
#[derive(Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub ecosystems: BTreeMap<String, EcosystemConfig>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let ecosystems = model::ECOSYSTEMS
            .iter()
            .map(|e| (e.slug.to_string(), EcosystemConfig::defaults_for(e.slug)))
            .collect();
        Self { ecosystems }
    }
}

impl AppConfig {
    /// Load settings from the repo [`defaults_dir`], merged over catalog defaults.
    pub fn load() -> Self {
        Self::load_from(&defaults_dir())
    }

    /// Load settings from `dir`, merged over the catalog defaults: a missing
    /// file leaves that ecosystem at defaults; a present file overrides the
    /// endpoint and the capability values it lists (unknown keys are ignored, so
    /// a removed capability is dropped and a newly added one defaults to on).
    pub fn load_from(dir: &Path) -> Self {
        let mut cfg = Self::default();
        for eco in model::ECOSYSTEMS {
            let Ok(bytes) = std::fs::read(ecosystem_path_in(dir, eco.slug)) else {
                continue;
            };
            let Ok(file) = serde_json::from_slice::<EcosystemFile>(&bytes) else {
                continue;
            };
            let Some(e) = cfg.ecosystems.get_mut(eco.slug) else {
                continue;
            };
            if !file.registry_endpoint.is_empty() {
                e.registry_endpoint = file.registry_endpoint;
            }
            for (k, v) in file.capabilities {
                if e.capabilities.contains_key(&k) {
                    e.capabilities.insert(k, v);
                }
            }
        }
        cfg
    }

    /// Reset a single ecosystem's endpoint to the catalog default.
    pub fn reset_endpoint(&mut self, slug: &str) {
        if let (Some(cfg), Some(eco)) = (self.ecosystems.get_mut(slug), model::ecosystem(slug)) {
            cfg.registry_endpoint = eco.default_endpoint.to_string();
        }
    }

    /// Toggle every supported capability for an ecosystem on or off.
    pub fn set_all_capabilities(&mut self, slug: &str, on: bool) {
        if let Some(cfg) = self.ecosystems.get_mut(slug) {
            for v in cfg.capabilities.values_mut() {
                *v = on;
            }
        }
    }
}

/// Resolve the repo defaults directory this app manages.
///
/// `MALSCAN_DEFAULTS_DIR` if set; else `<repo>/config/defaults`, located relative
/// to this crate (`CARGO_MANIFEST_DIR` is `<repo>/frontend`). These are the
/// committed files the Go engine embeds — distinct from the operator's system
/// override dir (`MALSCAN_CONFIG_DIR` / `os.UserConfigDir`), which the frontend
/// never writes.
pub fn defaults_dir() -> PathBuf {
    if let Ok(d) = std::env::var("MALSCAN_DEFAULTS_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    match crate_dir.parent() {
        Some(repo) => repo.join("config").join("defaults"),
        None => PathBuf::from("config/defaults"),
    }
}

/// Path of an ecosystem's config file within `dir`.
pub fn ecosystem_path_in(dir: &Path, slug: &str) -> PathBuf {
    dir.join(format!("{slug}.json"))
}

/// Path of an ecosystem's config file within the repo [`defaults_dir`].
pub fn ecosystem_path(slug: &str) -> PathBuf {
    ecosystem_path_in(&defaults_dir(), slug)
}

/// Path of the generated badnet feed/parser mapping embedded by the Go module.
pub fn feed_sources_path() -> PathBuf {
    if let Ok(p) = std::env::var("MALSCAN_FEED_SOURCES_PATH") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    match crate_dir.parent() {
        Some(repo) => repo.join("badnet").join("data").join("feeds.json"),
        None => PathBuf::from("badnet/data/feeds.json"),
    }
}

/// The pretty JSON that would be persisted for an ecosystem (used by the preview
/// tab and the on-disk write).
pub fn file_json(slug: &str, cfg: &EcosystemConfig) -> String {
    let file = EcosystemFile {
        ecosystem: slug.to_string(),
        registry_endpoint: cfg.registry_endpoint.clone(),
        capabilities: cfg.capabilities.clone(),
    };
    serde_json::to_string_pretty(&file).unwrap_or_else(|e| format!("// serialise error: {e}"))
}

/// Pretty JSON for the badnet feed/parser mapping.
pub fn feed_sources_json() -> String {
    let file = FeedSourcesFile {
        schema_version: "badnet-feeds/v1".to_string(),
        feeds: model::FEED_SOURCES
            .iter()
            .map(|f| FeedSourceFile {
                key: f.key.to_string(),
                name: f.name.to_string(),
                url: f.url.to_string(),
                parser: f.parser.to_string(),
                detail: f.detail.to_string(),
                enabled: true,
            })
            .collect(),
    };
    serde_json::to_string_pretty(&file).unwrap_or_else(|e| format!("// serialise error: {e}"))
}

/// Write an ecosystem's config to `<dir>/<slug>.json`, creating `dir` if needed.
/// Returns the written path and its byte length.
pub fn write_ecosystem_in(
    dir: &Path,
    slug: &str,
    cfg: &EcosystemConfig,
) -> std::io::Result<(PathBuf, usize)> {
    std::fs::create_dir_all(dir)?;
    let path = ecosystem_path_in(dir, slug);
    let json = format!("{}\n", file_json(slug, cfg)); // trailing newline for clean diffs
    std::fs::write(&path, json.as_bytes())?;
    Ok((path, json.len()))
}

/// Write an ecosystem's config into the repo [`defaults_dir`].
pub fn write_ecosystem(slug: &str, cfg: &EcosystemConfig) -> std::io::Result<(PathBuf, usize)> {
    write_ecosystem_in(&defaults_dir(), slug, cfg)
}

/// Write the badnet feed/parser mapping, creating the parent dir if needed.
pub fn write_feed_sources(path: &Path) -> std::io::Result<(PathBuf, usize)> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = format!("{}\n", feed_sources_json());
    std::fs::write(path, json.as_bytes())?;
    Ok((path.to_path_buf(), json.len()))
}

/// Write the catalog-default config file for every ecosystem into `dir`. Used by
/// the `--write-defaults` CLI to (re)generate the committed `config/defaults`
/// plus the badnet feed/parser mapping embedded by the Go module.
pub fn write_all_defaults(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let cfg = AppConfig::default();
    let mut written = Vec::with_capacity(model::ECOSYSTEMS.len() + 1);
    for eco in model::ECOSYSTEMS {
        let (path, _) = write_ecosystem_in(dir, eco.slug, &cfg.ecosystems[eco.slug])?;
        written.push(path);
    }
    let (path, _) = write_feed_sources(&feed_sources_path())?;
    written.push(path);
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_cover_all_ecosystems_with_everything_enabled() {
        let cfg = AppConfig::default();
        for eco in model::ECOSYSTEMS {
            let e = cfg.ecosystems.get(eco.slug).expect("ecosystem present");
            assert_eq!(e.registry_endpoint, eco.default_endpoint);
            let supported = model::capabilities_for(eco.slug).len();
            assert_eq!(e.capabilities.len(), supported);
            assert_eq!(e.enabled_count(), supported, "all caps default on");
        }
    }

    #[test]
    fn set_all_and_reset_endpoint() {
        let mut cfg = AppConfig::default();
        cfg.set_all_capabilities("npm", false);
        assert_eq!(cfg.ecosystems["npm"].enabled_count(), 0);

        cfg.ecosystems.get_mut("npm").unwrap().registry_endpoint = "https://evil.example".into();
        cfg.reset_endpoint("npm");
        assert_eq!(
            cfg.ecosystems["npm"].registry_endpoint,
            model::ecosystem("npm").unwrap().default_endpoint
        );
    }

    #[test]
    fn config_round_trips_through_json() {
        let cfg = AppConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let back: AppConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.ecosystems.len(), cfg.ecosystems.len());
        assert_eq!(
            back.ecosystems["aur"].capabilities,
            cfg.ecosystems["aur"].capabilities
        );
    }

    #[test]
    fn write_then_load_round_trips_on_disk() {
        let dir = std::env::temp_dir().join(format!("malscan-fe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut cfg = AppConfig::default();
        cfg.set_all_capabilities("npm", false);
        cfg.ecosystems.get_mut("npm").unwrap().registry_endpoint = "https://example.test".into();

        let (path, bytes) = write_ecosystem_in(&dir, "npm", &cfg.ecosystems["npm"]).expect("write");
        assert!(bytes > 0);
        assert!(path.exists());

        let loaded = AppConfig::load_from(&dir);
        // npm: persisted edits applied.
        assert_eq!(loaded.ecosystems["npm"].enabled_count(), 0);
        assert_eq!(
            loaded.ecosystems["npm"].registry_endpoint,
            "https://example.test"
        );
        // aur: no file → defaults retained.
        assert_eq!(
            loaded.ecosystems["aur"].enabled_count(),
            model::capabilities_for("aur").len()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_json_matches_go_shape() {
        let cfg = AppConfig::default();
        let json = file_json("npm", &cfg.ecosystems["npm"]);
        assert!(json.contains("\"ecosystem\": \"npm\""));
        assert!(json.contains("\"registry_endpoint\""));
        assert!(json.contains("\"capabilities\""));
    }

    #[test]
    fn feed_sources_json_maps_sources_to_parsers() {
        let json = feed_sources_json();
        assert!(json.contains("\"schema_version\": \"badnet-feeds/v1\""));
        assert!(json.contains("\"key\": \"crowdsec-intelligence\""));
        assert!(json.contains("\"parser\": \"misp\""));
        assert!(json.contains("\"key\": \"urlhaus-hosts\""));
        assert!(json.contains("\"parser\": \"hosts\""));
    }
}
