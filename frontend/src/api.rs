//! Persistence: writing an ecosystem's config to the shared config directory.
//!
//! The local JSON file IS the source of truth the Go engine reads, so [`save`]
//! writes it for real (via [`crate::config::write_ecosystem`]). Pushing the same
//! document to a remote backend is the remaining stub — see the `TODO(api)`.

use std::path::PathBuf;

use crate::config::{self, EcosystemConfig};

/// Result of a successful save: the file written and its byte length.
pub struct Outcome {
    pub path: PathBuf,
    pub bytes: usize,
}

/// Errors a save can surface.
#[derive(Debug)]
pub enum SaveError {
    Io(String),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaveError::Io(e) => write!(f, "write config: {e}"),
        }
    }
}

/// Persist one ecosystem's config to the shared config directory.
///
/// TODO(api): once a backend exists, also POST the same document to
/// `{base}/api/ecosystems/{slug}/config`. The on-disk file remains the source of
/// truth the engine reads, so persistence does not depend on the network.
pub fn save(slug: &str, cfg: &EcosystemConfig) -> Result<Outcome, SaveError> {
    let (path, bytes) =
        config::write_ecosystem(slug, cfg).map_err(|e| SaveError::Io(e.to_string()))?;
    Ok(Outcome { path, bytes })
}
