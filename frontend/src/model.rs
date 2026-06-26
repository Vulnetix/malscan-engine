//! The engine model, mirrored for the UI.
//!
//! Two static catalogs describe what the `malscan-engine` can do:
//!
//!   * [`ECOSYSTEMS`] — the registry slugs the engine recognises
//!     (`detect/model.go`, `PackageContext.Ecosystem`), with a sensible default
//!     registry endpoint for each.
//!   * [`CAPABILITIES`] — every detector / supporting module the engine runs,
//!     with the set of ecosystems for which it is meaningful.
//!
//! The `engine_ref` field on each capability names the Go symbol / signal-id
//! family it maps to, so this table can be checked against the engine source.
//!
//! Support matrix rationale (grounded in the Go source):
//!   * Content detectors that run over `PkgbuildContent` / `InstallScriptContent`
//!     (`detect/engine.go::Detect`) apply to every ecosystem — every processor
//!     maps its primary build/manifest script into `PkgbuildContent`.
//!   * `install-script` is restricted to registries with lifecycle/install hooks
//!     (AUR `.install`, Homebrew `post_install`, npm pre/post-install, PyPI
//!     `setup.py`, RubyGems `extconf.rb`, NuGet `init.ps1`); Go and Cargo have no
//!     equivalent install hook (Cargo's `build.rs` is a *build* script and maps
//!     to `PkgbuildContent`).
//!   * `checksum` parses PKGBUILD-style inline `sha256sums=()` arrays
//!     (`detect/checksum.go`) — AUR and Homebrew only.
//!   * `bin-source` keys off the AUR `-bin` suffix convention
//!     (`detect/binsource.go`).
//!   * `orphan-takeover` / `git-history` need a maintainer identity plus package
//!     git history — the git-backed registries (AUR, Homebrew).
//!   * `registry-comments` scans registry comment bodies, which only AUR has.

use eframe::egui::Color32;

/// A registry the engine can label findings for.
pub struct Ecosystem {
    /// Registry slug used by `PackageContext.Ecosystem` (e.g. `"npm"`).
    pub slug: &'static str,
    /// Human-friendly name shown in the switcher.
    pub name: &'static str,
    /// Default registry API endpoint (editable in the UI, saved via the stub API).
    pub default_endpoint: &'static str,
}

/// The registry slugs from `detect/model.go` (`PackageContext.Ecosystem`).
pub const ECOSYSTEMS: &[Ecosystem] = &[
    Ecosystem {
        slug: "aur",
        name: "Arch User Repository",
        default_endpoint: "https://aur.archlinux.org/rpc/v5",
    },
    Ecosystem {
        slug: "homebrew",
        name: "Homebrew",
        default_endpoint: "https://formulae.brew.sh/api",
    },
    Ecosystem {
        slug: "npm",
        name: "npm",
        default_endpoint: "https://registry.npmjs.org",
    },
    Ecosystem {
        slug: "pypi",
        name: "PyPI",
        default_endpoint: "https://pypi.org/pypi",
    },
    Ecosystem {
        slug: "rubygems",
        name: "RubyGems",
        default_endpoint: "https://rubygems.org/api/v1",
    },
    Ecosystem {
        slug: "go",
        name: "Go modules",
        default_endpoint: "https://proxy.golang.org",
    },
    Ecosystem {
        slug: "cargo",
        name: "crates.io",
        default_endpoint: "https://crates.io/api/v1",
    },
    Ecosystem {
        slug: "nuget",
        name: "NuGet",
        default_endpoint: "https://api.nuget.org/v3/index.json",
    },
];

/// Look up an ecosystem by slug.
pub fn ecosystem(slug: &str) -> Option<&'static Ecosystem> {
    ECOSYSTEMS.iter().find(|e| e.slug == slug)
}

/// Best ecosystem match for a free-text query (the type-ahead "jump" box).
///
/// Priority: an exact slug/name match, then a prefix match, then a substring
/// match — so typing `r` lands on RubyGems, `ru` still RubyGems, `c` on crates,
/// `nu` on NuGet. Matching is case-insensitive; an empty query matches nothing.
pub fn match_ecosystem(query: &str) -> Option<&'static str> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return None;
    }
    let mut prefix: Option<&'static str> = None;
    let mut substr: Option<&'static str> = None;
    for e in ECOSYSTEMS {
        let slug = e.slug.to_lowercase();
        let name = e.name.to_lowercase();
        if slug == q || name == q {
            return Some(e.slug);
        }
        if prefix.is_none() && (slug.starts_with(&q) || name.starts_with(&q)) {
            prefix = Some(e.slug);
        }
        if substr.is_none() && (slug.contains(&q) || name.contains(&q)) {
            substr = Some(e.slug);
        }
    }
    prefix.or(substr)
}

/// How the engine classes a capability's findings — mirrors `detect.Class`
/// (`evidence` / `trigger` / `context`) plus a `Module` bucket for the
/// supporting packages (`ioc`, `badhash`, `goodkeys`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Factual malicious evidence — any one finding mints on its own.
    Evidence,
    /// Weak corroborating signal — only mints in combination (the gate).
    Trigger,
    /// Reputation/risk signal — recorded as metadata, never mints alone.
    Context,
    /// A supporting engine module rather than a `Detect` detector.
    Module,
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Class::Evidence => "evidence",
            Class::Trigger => "trigger",
            Class::Context => "context",
            Class::Module => "module",
        }
    }

    /// Chip colour for the class badge.
    pub fn color(self) -> Color32 {
        match self {
            Class::Evidence => Color32::from_rgb(0xd9, 0x4f, 0x4f), // red — mints
            Class::Trigger => Color32::from_rgb(0xd9, 0x95, 0x3f),  // amber — combines
            Class::Context => Color32::from_rgb(0x5b, 0x8d, 0xc9),  // blue — metadata
            Class::Module => Color32::from_rgb(0x4f, 0xa6, 0x7a),   // green — module
        }
    }
}

/// Which ecosystems a capability applies to.
pub enum Support {
    /// Every ecosystem.
    All,
    /// Only the listed slugs.
    Only(&'static [&'static str]),
}

impl Support {
    pub fn includes(&self, slug: &str) -> bool {
        match self {
            Support::All => true,
            Support::Only(slugs) => slugs.contains(&slug),
        }
    }
}

/// One engine capability (a `Detect` detector or a supporting module).
pub struct Capability {
    /// Stable key used in the config map and the save payload.
    pub key: &'static str,
    /// Display name.
    pub name: &'static str,
    /// One-line description (shown as a hover tooltip).
    pub detail: &'static str,
    /// Finding class.
    pub class: Class,
    /// Go symbol / signal-id family this maps to, for cross-checking the engine.
    pub engine_ref: &'static str,
    /// Ecosystems this capability is meaningful for.
    pub support: Support,
}

/// The full capability catalog, ordered roughly strongest-evidence first.
pub const CAPABILITIES: &[Capability] = &[
    Capability {
        key: "manifest-patterns",
        name: "Manifest / build-script patterns",
        detail: "Download-and-execute, reverse shells, eval/base64 and other patterns matched against the primary build/manifest script.",
        class: Class::Evidence,
        engine_ref: "detect.Detect → pkgbuild_analysis",
        support: Support::All,
    },
    Capability {
        key: "source-url-patterns",
        name: "Source-URL patterns",
        detail: "Suspicious download URLs declared by the manifest (paste sites, IP literals, shorteners).",
        class: Class::Evidence,
        engine_ref: "detect.Detect → source_url_analysis",
        support: Support::All,
    },
    Capability {
        key: "gtfobins",
        name: "GTFOBins LOLBin analysis",
        detail: "Living-off-the-land binary invocations used to execute, escalate or exfiltrate.",
        class: Class::Evidence,
        engine_ref: "detect.Detect → gtfobins_analysis",
        support: Support::All,
    },
    Capability {
        key: "shell-obfuscation",
        name: "Shell-obfuscation & high-entropy heredoc",
        detail: "Variable-concat exec, obfuscation, and the SA-HIGH-ENTROPY-HEREDOC payload trigger (combines via the gate).",
        class: Class::Evidence,
        engine_ref: "detect.analyzeShell (SA-*)",
        support: Support::All,
    },
    Capability {
        key: "install-script",
        name: "Install-hook script analysis",
        detail: "Runs the pattern + shell detectors over install/lifecycle hooks (AUR .install, npm pre/post-install, init.ps1, …).",
        class: Class::Evidence,
        engine_ref: "detect.Detect → install_script_analysis",
        support: Support::Only(&["aur", "homebrew", "npm", "pypi", "rubygems", "nuget"]),
    },
    Capability {
        key: "onion-c2",
        name: "Tor .onion C2 / exfil source",
        detail: "A .onion address in the manifest, install scripts or latest diff — a common C2/exfil channel.",
        class: Class::Evidence,
        engine_ref: "detect.analyzeOnion (P-ONION-C2)",
        support: Support::All,
    },
    Capability {
        key: "homograph",
        name: "IDN homograph / mixed-script URL",
        detail: "Mixed-script (Latin+Cyrillic/Greek) hostnames in source URLs — a review-evasion technique (CWE-1007).",
        class: Class::Evidence,
        engine_ref: "detect.analyzeHomograph",
        support: Support::All,
    },
    Capability {
        key: "name-typosquat",
        name: "Typosquat / brand-impersonation",
        detail: "Package names impersonating popular packages or brands via look-alike or impersonation suffixes.",
        class: Class::Evidence,
        engine_ref: "detect.analyzeName",
        support: Support::All,
    },
    Capability {
        key: "bin-source",
        name: "`-bin` source/upstream verification",
        detail: "A -bin package whose download host differs from its declared upstream (AUR binary-package convention).",
        class: Class::Evidence,
        engine_ref: "detect.analyzeBinSource",
        support: Support::Only(&["aur"]),
    },
    Capability {
        key: "ownership-hijack",
        name: "Ownership / hijack triggers",
        detail: "Cross-registry ownership-transfer, orphan-adoption, new-maintainer and known-bad-owner triggers (the combination gate).",
        class: Class::Trigger,
        engine_ref: "detect.OwnershipTriggers (MT-*)",
        support: Support::All,
    },
    Capability {
        key: "orphan-takeover",
        name: "Orphan / abandonment takeover",
        detail: "Submitter≠maintainer plus a new git author on an established package — an orphan-takeover pattern.",
        class: Class::Evidence,
        engine_ref: "detect.analyzeOrphanTakeover",
        support: Support::Only(&["aur", "homebrew"]),
    },
    Capability {
        key: "manifest-diff",
        name: "Build-script revision diff",
        detail: "Newly introduced network calls or changed checksum/source between the prior and current manifest revision.",
        class: Class::Evidence,
        engine_ref: "detect.analyzePkgbuildDiff",
        support: Support::All,
    },
    Capability {
        key: "git-history",
        name: "Git-history temporal analysis",
        detail: "Single-commit history, package age and author-change signals from the package's source repo.",
        class: Class::Context,
        engine_ref: "detect.analyzeGitHistory",
        support: Support::Only(&["aur", "homebrew"]),
    },
    Capability {
        key: "checksum",
        name: "Checksum / integrity hygiene",
        detail: "Missing, all-SKIP or weak (md5/sha1) checksum arrays in the manifest (PKGBUILD-style sha256sums).",
        class: Class::Context,
        engine_ref: "detect.analyzeChecksum",
        support: Support::Only(&["aur", "homebrew"]),
    },
    Capability {
        key: "metadata-reputation",
        name: "Reputation metadata",
        detail: "Votes/popularity, missing license/URL and orphan flags — risk context, never mints alone.",
        class: Class::Context,
        engine_ref: "detect.analyzeMetadata",
        support: Support::All,
    },
    Capability {
        key: "maintainer-batch",
        name: "Maintainer batch-upload analysis",
        detail: "Detects a maintainer pushing many packages at once — a mass-upload supply-chain pattern.",
        class: Class::Context,
        engine_ref: "detect.analyzeMaintainer",
        support: Support::All,
    },
    Capability {
        key: "github-stars",
        name: "Upstream GitHub reputation",
        detail: "Low-star or 404 upstream GitHub repositories — a weak credibility signal.",
        class: Class::Context,
        engine_ref: "detect.analyzeGithubStars",
        support: Support::All,
    },
    Capability {
        key: "registry-comments",
        name: "Registry comment scanning",
        detail: "Scans recent registry comment bodies for warning signals (AUR has user comments).",
        class: Class::Context,
        engine_ref: "detect.analyzeAurComments",
        support: Support::Only(&["aur"]),
    },
    Capability {
        key: "badhash",
        name: "Known-bad artifact-hash set",
        detail: "Case-insensitive known-bad hash set (embedded seed + MalwareIoc rows) — a hash hit mints on its own.",
        class: Class::Module,
        engine_ref: "badhash.Set",
        support: Support::All,
    },
    Capability {
        key: "ioc-extract",
        name: "IOC + artifact-hash extraction",
        detail: "Extracts domains, URLs, IPs, file hashes, install commands, wallets and exfil endpoints from a package.",
        class: Class::Module,
        engine_ref: "ioc.Extract",
        support: Support::All,
    },
    Capability {
        key: "goodkeys",
        name: "Known-good signing-key allowlist",
        detail: "Allowlists trusted platform signing keys/identities (GitHub web-flow, Dependabot, …) to suppress false positives.",
        class: Class::Module,
        engine_ref: "goodkeys.Set",
        support: Support::All,
    },
    Capability {
        key: "ioc-scan",
        name: "STIX domain/IP IOC filesystem scan",
        detail: "Pulls domain/IP/URL indicators from the public STIX feeds (cached to the OS temp dir with a TTL) and scans a working directory — and optionally ELF binaries — for files referencing known-bad infrastructure.",
        class: Class::Module,
        engine_ref: "iocscan.Scan",
        support: Support::All,
    },
];

/// The capabilities supported by a given ecosystem, in catalog order.
pub fn capabilities_for(slug: &str) -> Vec<&'static Capability> {
    CAPABILITIES
        .iter()
        .filter(|c| c.support.includes(slug))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(slug: &str) -> usize {
        capabilities_for(slug).len()
    }

    #[test]
    fn capability_keys_are_unique() {
        let mut keys: Vec<&str> = CAPABILITIES.iter().map(|c| c.key).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate capability key in catalog");
    }

    #[test]
    fn every_ecosystem_supports_something() {
        for eco in ECOSYSTEMS {
            assert!(count(eco.slug) > 0, "{} supports no capabilities", eco.slug);
        }
    }

    #[test]
    fn aur_supports_every_capability() {
        // AUR is the engine's reference ecosystem (the traur origin); every
        // detector applies to it.
        assert_eq!(count("aur"), CAPABILITIES.len());
    }

    #[test]
    fn support_matrix_matches_engine() {
        // Counts derived from the per-capability support sets — a guard against
        // accidental matrix edits.
        assert_eq!(count("aur"), 22);
        assert_eq!(count("homebrew"), 20); // no -bin, no registry-comments
        assert_eq!(count("npm"), 17); // +install-script over the 16 universal
        assert_eq!(count("pypi"), 17);
        assert_eq!(count("rubygems"), 17);
        assert_eq!(count("nuget"), 17);
        assert_eq!(count("go"), 16); // universal only — no install hooks
        assert_eq!(count("cargo"), 16);
    }

    #[test]
    fn install_script_excludes_go_and_cargo() {
        for slug in ["go", "cargo"] {
            assert!(
                !capabilities_for(slug)
                    .iter()
                    .any(|c| c.key == "install-script"),
                "{slug} should not list install-script"
            );
        }
    }

    #[test]
    fn ecosystem_lookup_round_trips() {
        for eco in ECOSYSTEMS {
            assert_eq!(ecosystem(eco.slug).map(|e| e.slug), Some(eco.slug));
        }
        assert!(ecosystem("does-not-exist").is_none());
    }

    #[test]
    fn jump_matcher_resolves_typeahead() {
        assert_eq!(match_ecosystem(""), None);
        assert_eq!(match_ecosystem("npm"), Some("npm")); // exact slug
        assert_eq!(match_ecosystem("Homebrew"), Some("homebrew")); // exact name
        assert_eq!(match_ecosystem("ru"), Some("rubygems")); // prefix
        assert_eq!(match_ecosystem("crat"), Some("cargo")); // name prefix → crates.io
        assert_eq!(match_ecosystem("nu"), Some("nuget")); // prefix
        assert_eq!(match_ecosystem("zzz"), None);
    }
}
