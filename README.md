<p align="center">
  <img src="pix-contemplative.svg" alt="Pix in analyst mode, the Vulnetix mascot" width="120">
</p>

# malscan-engine

Shared Go module for Vulnetix malicious-package detection. Consumed by both the
VDB processors (`vdb-manager`) and the `package-firewall`.

## Packages

| Package | Purpose |
|---------|---------|
| `detect` | Malicious-PKGBUILD/formula detection engine (Go port of [traur](https://github.com/Sohimaster/traur), MIT). Pattern + behavioural detectors emit `Finding`s classed `evidence` (mints alone), `trigger` (combines with a high-entropy payload), or `context` (metadata only). `IsMaliciousCombined` applies the combination gate. |
| `ioc` | Indicator-of-compromise + artifact-hash extraction from a package's PKGBUILD/install-scripts/latest-diff. |
| `badhash` | Case-insensitive known-bad artifact-hash set: an embedded seed list, augmentable at runtime with `MalwareIoc` file-hash rows from the shared database. |
| `goodkeys` | ALLOWLIST of known-good infrastructure signing keys/identities (GitHub `web-flow` GPG key `4AEE18F83AFDEB23`, `github-actions[bot]`, Dependabot, GitLab web-commit). Threat-actor key/email enrichment **MUST call `goodkeys.New().IsKnownGood(token)` / `IsKnownGoodEmail(email)` FIRST** and skip the DB/registry/GitHub-API actor-key lookup on a hit — a web-merged commit is signed by GitHub, not the attacker. Hardcoded, provenance-commented list; runtime-augmentable via `AddKey`/`AddEmail`. |
| `config` | Per-ecosystem capability configuration: committed repo defaults (`config/defaults/*.json`, embedded via `//go:embed`) overlaid by optional system overrides. Lets an operator disable detectors for a registry and have the engine **short-circuit them at runtime** — no rebuild. See [Configuration](#configuration-how-the-go-modules-read-it). |
| `iocscan` | STIX domain/IP/URL IOC **filesystem scan** (`ioc-scan` capability). Pulls indicators from the public STIX feeds, caches them to the OS temp dir with a TTL, then walks a working directory — and optionally ELF binaries — returning evidence (host + path + file-content context) for any file referencing known-bad infrastructure. Stateless and stdlib-only. See [STIX IOC filesystem scan](#stix-ioc-filesystem-scan-iocscan). |

## Configuration: how the Go modules read it

Per-ecosystem capability configuration controls which detectors the engine runs
for a given registry, so an operator can disable noisy or irrelevant detectors
and have the engine **short-circuit them at runtime — no rebuild**. Each config
is one JSON document per ecosystem:

```json
{
  "ecosystem": "npm",
  "registry_endpoint": "https://registry.npmjs.org",
  "capabilities": { "manifest-patterns": true, "checksum": false }
}
```

### Two layers (lowest precedence first)

1. **Committed repo defaults** — `config/defaults/<slug>.json`, version-controlled
   in this repo and **embedded into the binary** by the `config` package
   (`//go:embed defaults/*.json`). They travel with the compiled engine, so a
   baseline is always present wherever a consumer runs — even when this module is
   pulled in as a Go dependency. These are authored/maintained by the `frontend/`
   app (and regenerated with `just gen-defaults`).
2. **System overrides** — `<override-dir>/<slug>.json` on the host machine, edited
   by an operator. The override dir is `config.Dir()`: `MALSCAN_CONFIG_DIR` if
   set, else `<user-config-dir>/malscan-engine` (`os.UserConfigDir` —
   `$XDG_CONFIG_HOME` or `$HOME/.config` on Linux). The frontend never writes
   here; it manages the repo defaults only.

### Merge & precedence

`config.Resolve(dir, slug)` (or `config.ResolveDefault(slug)`, which uses
`config.Dir()`) returns the **effective** config: the embedded default, overlaid
by the override file **per key** (and the `registry_endpoint`, if the override
sets a non-empty one). So a partial override like `{"capabilities":{"checksum":false}}`
changes only `checksum` and inherits the rest from the committed default.

Resolution of a single capability:

| Embedded default | System override | Effective |
|------------------|-----------------|-----------|
| `true`           | absent          | enabled   |
| `true`           | `false`         | disabled  |
| `false`          | `true`          | enabled   |
| absent           | absent          | enabled (default-on) |

`Enabled` treats a nil config, a nil map, or an absent key as **enabled** — so a
config records only what a human turned *off*, and a newly added detector still
runs against an older config.

### Wiring it into a scan

A processor resolves the config once per package (the read is cheap, so edits are
picked up live) and hands the capability map to the engine:

```go
ec, _ := config.ResolveDefault(ctx.Ecosystem) // embedded default ⊕ system override
ctx.Capabilities = ec.Capabilities            // nil ⇒ every detector runs
findings := detect.Detect(ctx)                // detectors set false are skipped

// detectors invoked outside Detect (ownership/badhash/ioc/goodkeys):
if ec.Enabled(detect.CapBadHash) {
    // … run the known-bad-hash gate
}
```

`detect.Detect` consults `PackageContext.Capabilities` for every detector; a nil
map (the zero value) runs everything, so callers that don't load config are
unaffected. Capability keys are the contract shared by `detect` (the `Cap*`
constants), the `config` package, and the frontend (`frontend/src/model.rs`).

## Detection model

- A single `evidence` finding marks a package malicious (download-and-execute,
  reverse shells, exfil, GTFObins, a Tor `.onion` C2 source, or an artifact hash
  matching the known-bad set).
- A high-entropy payload is a `trigger`, not standalone evidence — it mints only
  in combination with at least one other distinct trigger (new reporter /
  maintainer / contributor, or a changed maintainer/contributor email). Entropy
  alone never mints; metadata-only combinations never mint.

## STIX IOC filesystem scan (`iocscan`)

`iocscan` is a network-and-filesystem capability — unlike the `detect` package
(a pure content analyzer over pre-loaded strings), it fetches the public STIX 2.1
feeds and walks the filesystem. It stays **standalone and stateless**: each call
is self-contained, the only persistent side effect is a shared on-disk feed cache,
and operational notices come back **in the result** as `Warning`s (the engine owns
no logger). It is invoked **outside** `detect.Detect` and gated via
`config.EcosystemConfig.Enabled(detect.CapIOCScan)`, like `badhash`/`ioc`/`goodkeys`.

```go
report, err := iocscan.Scan(iocscan.Options{
    Root:           ".",                       // working directory to scan
    Ecosystem:      "npm",                     // the "generic" feed is always merged in too
    Depth:          3,                          // max directory depth (<=0 = unlimited)
    IncludeExt:     []string{".js", ".json"},   // allowlist (empty = all)
    ExcludeExt:     []string{".min.js"},        // skiplist (takes precedence)
    BinaryAnalysis: true,                       // also string-scan ELF / binary files
    ContextLines:   3,                          // lines of context above & below a hit
    TTL:            time.Hour,                  // feed-cache freshness (default 1h)
})
for _, ev := range report.Evidence {
    // ev.IndicatorType / ev.IndicatorValue / ev.Indicator (STIX provenance)
    // ev.FilePath / ev.LineNumber / ev.MatchedLine / ev.ContextBefore / ev.ContextAfter
    finding := ev.ToFinding() // adapt to a detect.Finding (ClassEvidence, CWE-506)
}
```

A processor that only wants the indicator set (e.g. to match its own data) can use
`(*FeedLoader).Load(ecosystems...)` directly, which returns the merged
`*IndicatorSet` plus any `Warning`s.

### In-memory matching (no filesystem)

`Scan` walks a directory, but a high-volume caller (a registry processor scanning every
package's already-in-memory source) wants to load the feed **once** and match many content
buffers without touching disk or re-parsing the feed per item. Use the `Matcher`:

```go
loader := &iocscan.FeedLoader{}                 // public index + tmp cache + TTL
set, warns, err := loader.Load("npm")           // load ONCE per run; reuse `set`
m := iocscan.NewMatcher(set, 3)                 // 3 context lines
for _, pkg := range packages {
    ev := m.MatchText(pkg.Name+"/index.js", pkg.SourceText) // []Evidence with line + context
    // m.MatchBytes(name, data) auto-detects ELF/binary and extracts strings
    findings := make([]detect.Finding, 0, len(ev))
    for _, e := range ev {
        findings = append(findings, e.ToFinding()) // ClassEvidence, CWE-506 → folds into the verdict
    }
}
```

`Scan` itself uses a `Matcher` internally, so the filesystem and in-memory paths share identical
matching, evidence shape and dedup. Passing `Options{Set: preloaded}` to `Scan` likewise skips
the loader and scans against an already-loaded set.

### Feed cache (temp dir, timestamped, TTL)

The index (`https://vulnetix.com/malscan-stix/index.json`) and each per-ecosystem
`dns`/`urls` bundle are cached under `os.TempDir()` as
`malscan-stix-<ecosystem>-<kind>-<unixNano>.json`. Freshness is decided from the
**timestamp encoded in the filename** (located via glob — no sidecar metadata):
within the TTL the cached copy is used silently; past it the feed is refetched,
sha256-verified against the index, written atomically (temp + rename, so concurrent
processors never see a partial file), and older copies are pruned. If a refetch
fails (offline) or its checksum mismatches, the newest cached copy is used and a
`stale-cache` / `checksum-mismatch` `Warning` is returned; if no cache exists at
all, `Load`/`Scan` returns an error.

## Consumers

- `vdb-manager` — `aur-fetch-processor`, `homebrew-fetch-processor` (detection +
  hash check + IOC extraction). Wired via a `replace` directive during local
  development.
- `package-firewall` — loads the `badhash` set (embedded + `MalwareIoc`) to gate
  digest-bearing package requests.
