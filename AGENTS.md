# AGENTS.md — malscan-engine

Operating guide for AI agents and contributors working in this repository. For
end-user/consumer documentation see `README.md`; this file captures the
**architecture, business rules, hard constraints, dependencies, use cases**, and
the **rules of engagement** an agent must respect before changing anything.

---

## 1. What this is

`malscan-engine` is a **pure-Go** library that decides whether a software package
is malicious by analysing its build/manifest scripts, install hooks, source, and
declared artifacts. It is consumed in-process by other Vulnetix services — it is
**not** a standalone application (the user-facing CLI lives in the `cli` repo as
`malscan`). A small **Rust (egui) frontend** is a *configuration editor* for the
engine's per-ecosystem capability files; it is not part of the detection path.

Detection philosophy (do not violate): **no single primitive is a verdict —
malice is the co-occurrence of a capability and a threat-indicator in the same
auto-execution surface. The engine records the *intent of the usage* so a
reviewer can tell a malicious use from a benign one.** Score the combination and
the surface, never the keyword alone.

---

## 2. Architecture

| Package | Role |
|---------|------|
| `detect` | The engine. `Detect(ctx)` runs every enabled detector over a `PackageContext` and returns `[]Finding`. Pattern detectors (`data/patterns.toml`, compiled in `patterns.go`), behavioural detectors (`shell.go`, `onion.go`, `homograph.go`, `name.go`, `temporal.go`, `ownership.go`, `metadata.go`, `binsource.go`, `checksum.go`), and the multi-line registry-native TTP detector (`behaviors.go`). |
| `detect` (qualification) | `qualify.go` maps every signal id to a `Qualification{Intent, Tactic, Behavior, Differentiator}` — the documented bad-actor behaviour and the **benign-vs-malicious differentiator**. This is *advisory metadata* attached to findings; it does **not** change the mint/verdict (Class still gates that). |
| `ioc` | Extracts IOCs + artifact hashes (domains, URLs, IPs, hashes, install commands, wallets, exfil endpoints) from a package. Uses `allow` so benign values are never minted. |
| `badhash` | Case-insensitive known-bad artifact-hash set (embedded seed + runtime `MalwareIoc` rows). A hash hit is `evidence`. |
| `goodkeys` | Allowlist of known-good signing keys/identities (GitHub web-flow GPG, `github-actions[bot]`, Dependabot, GitLab web-commit). **Must be checked FIRST** before any DB/registry/GitHub-API actor lookup. |
| `allow` | Single source of truth for benign indicators (reserved/placeholder IPs, example/docs/registry/CDN/standards domains). Consumed by `ioc` (producer), `iocscan` (matcher), and the `vdb-manager` STIX build, so every layer shares one conservative list and cannot drift. |
| `config` | Per-ecosystem capability config: committed defaults (`config/defaults/*.json`, `//go:embed`) overlaid by optional host system overrides. Gates which detectors run, at runtime, no rebuild. |
| `iocscan` | STIX 2.1 domain/IP/URL IOC matcher. Filesystem walk (`Scan`) or in-memory (`NewMatcher`/`MatchText`/`MatchBytes`) over cached public STIX feeds. The only network-touching package. |
| `frontend/` (Rust) | egui config editor + `--write-defaults` generator for `config/defaults/*.json`. The catalog (`frontend/src/model.rs` `ECOSYSTEMS`/`CAPABILITIES`) is the source of truth the JSON is generated from. |

**Scan flow:** a processor builds a `PackageContext` (maps the package's primary
build/manifest into `PkgbuildContent`, install hooks into `InstallScriptContent`,
sets `Ecosystem` and `PkgbuildExecutes`), resolves config
(`config.ResolveDefault(slug)` → `ctx.Capabilities`), calls `detect.Detect(ctx)`,
then `detect.CombinedVerdict(findings)` (or `IsMaliciousCombined`). Detectors that
do I/O (`iocscan`, `badhash`, `ioc`, `goodkeys`) are invoked **outside** `Detect`
and gated via `config.EcosystemConfig.Enabled`.

---

## 3. Business rules (invariants — do not break)

1. **Factual-only minting.** The engine does **not** compute a weighted trust
   score/tier (unlike its `traur` origin). A package is malicious iff it has ≥1
   `ClassEvidence` finding, OR the combination gate fires. See `detect/model.go`
   header.
2. **The three classes.** `ClassEvidence` mints alone. `ClassTrigger` never mints
   alone — it combines (high-entropy payload + an identity/ownership trigger, or
   ≥2 independent identity families with a change-family). `ClassContext` is
   reputation/risk metadata and never mints.
3. **The combination gate** (`CombinedVerdict`, P0–P4): P0 any evidence; P4 owner
   is a known-bad actor; P1/P2 payload trigger + ≥1 identity trigger; P3 ≥2
   independent identity families incl. ≥1 change family. Pure-newness and
   single-ownership-change never mint.
4. **Intent qualification is mandatory metadata, not a gate.** Every finding can
   be qualified (`Qualify`) with its intent + benign-vs-malicious differentiator.
   Adding a new signal SHOULD add a `qualRegistry` entry; unknown signals fall
   back to the dual-use default.
5. **Surface decides dual-use.** A `hook_only`/dual-use command is `evidence`
   only in an auto-execution surface (install hook, or `PkgbuildContent` with
   `PkgbuildExecutes=true`); elsewhere it is corroboration (`ClassContext`).
   `override_gate` rules (reverse/bind shells, `curl|sh`) mint on any surface.
6. **goodkeys first.** Actor-key enrichment must call `goodkeys` before any
   DB/registry/GitHub lookup — a web-merged commit is signed by GitHub, not the
   attacker.
7. **Allowlist stays conservative.** Only unambiguously non-indicative values go
   in `allow`; never allowlist something that could be a real C2/exfil host.
8. **Capabilities default-on.** A nil map, nil config, or absent key = enabled.
   Config records only what a human turned *off*; a newly added detector still
   runs against an older config.

---

## 4. Hard constraints

- **Pure Go.** The **only** Go dependency is `github.com/BurntSushi/toml`
  (pattern DB + config parsing). Do not add Go dependencies. All else is stdlib.
- **RE2 only.** `patterns.toml` regexes compile under Go's `regexp` (no
  lookaround/backreferences). Rules that fail to compile are skipped, not fatal
  (`detect.SkippedPatterns()` must stay empty in CI).
- **STIX is the only network I/O**, and it is **cached** (OS temp dir,
  timestamped filename, TTL, sha256-verified, atomic write, offline stale-cache
  fallback). Any *new* online data source must reuse this cached pattern
  (`iocscan/feed.go`) — fetch-once, cache, TTL, offline fallback, no per-item
  network.
- **Stateless, no logger.** The engine owns no logger; operational notices are
  returned in results as `Warning`s. Detection (`detect`) is a pure content
  analyzer over pre-loaded strings.
- **Cross-language contract** (see §5) must stay in sync.

---

## 5. The capability/qualification contract (keep in sync)

Capability keys are shared across **three** places. Changing detectors means
editing all of them in one change:

1. **Go** — `detect/capabilities.go` (`Cap*` constants) + wire the detector into
   `detect.Detect` (or document it as invoked-outside-Detect).
2. **Rust** — `frontend/src/model.rs` `CAPABILITIES` (key/name/detail/class/
   `engine_ref`/`support`). Update the support-matrix tests
   (`support_matrix_matches_engine`, `aur_supports_all_but_registry_native`).
3. **JSON** — regenerate `config/defaults/*.json` with `just gen-defaults`
   (the Rust app is the generator; `defaults_dir()` always targets this repo's
   `config/defaults` via `CARGO_MANIFEST_DIR`).

`Support::All` = offered to every ecosystem; `Support::Only(&[...])` = restricted
to where the detector is *meaningful* (e.g. `install-script` only where lifecycle
hooks exist; `bad-actor-behaviors` only npm/pypi/rubygems/cargo/nuget, whose
registry-native TTPs the detector recognises).

---

## 6. Dependencies and their use cases

| Dependency | Where | Use case |
|------------|-------|----------|
| `github.com/BurntSushi/toml` | `detect` | Parse `data/patterns.toml` (rule DB) and TOML config. |
| Go stdlib (`regexp`, `net`, `encoding/json`, `crypto/sha256`, `net/http`, `embed`, …) | all | Matching, IP parsing, STIX fetch/parse/cache, embedded defaults. |
| `eframe`/`egui` (Rust) | `frontend` | Native config editor UI. |
| `serde`/`serde_json` (Rust) | `frontend` | (De)serialise `config/defaults/*.json`. |

---

## 7. Use cases for the engine

- **`vdb-manager` processors** (`aur-fetch-processor`, `homebrew-fetch-processor`,
  npm/pypi/etc.): detection + known-bad-hash check + IOC extraction during
  registry ingestion; builds the STIX feed (shares `allow`).
- **`package-firewall`**: loads the `badhash` set to gate digest-bearing package
  install requests.
- **`cli` repo `malscan` command**: in-process scan of installed dependencies
  (node_modules, site-packages, vendor, ~/.cargo) producing SARIF — runs
  `detect` + `iocscan` + `ioc` + `badhash` offline.
- **High-volume registry scanning**: load the STIX feed once
  (`FeedLoader.Load`) and reuse a `Matcher` across every package in memory.

---

## 8. Build, test, verify

```sh
# Go engine
go build ./...        # or: just go-build
go vet ./...          # or: just go-vet
go test ./...         # or: just go-test

# Rust config frontend (from repo root; recipes cd into frontend/)
just test             # cargo test
just clippy           # cargo clippy --all-targets -D warnings
just run              # launch the egui editor
just gen-defaults     # regenerate config/defaults/*.json from the catalog

just check            # full gate: fmt-check + clippy + cargo test + go vet + go test
```

After any capability change: `just gen-defaults` then `git diff config/defaults`
must be a **purely additive** change matching the catalog edit.

---

## 9. Rules of engagement for agents

- **This repo is developed across concurrent sessions.** Before editing a file,
  re-read its current state; `detect/` and `iocscan/` are frequently active.
  Make **additive** changes, prefer new files over rewrites, and **never revert
  or overwrite** another session's work. Check `git status` before/after.
- **Stay in your lane.** If your task is config/frontend exposure, do not edit
  `detect/` engine internals; if your task is a new detector, follow §5 to wire
  it through all three layers.
- **Resilience.** On a failed build/test/agent/network step, wait briefly and
  retry; for an account session-limit, defer rather than hammer.
- **Respect the invariants** in §3 and the constraints in §4. New rules must
  compile under RE2 and carry an intent qualification.

---

## 10. Appendix — intent-qualification taxonomy (deep-research distilled)

The benign-vs-malicious differentiators below are distilled from per-ecosystem
threat research (each campaign corroborated by ≥2 of: Socket, Phylum, Snyk,
Checkmarx, ReversingLabs, JFrog, Datadog Security Labs, Sonatype, OpenSSF/OSV,
GitHub Advisory DB; academic *Backstabber's Knife Collection* arXiv:2005.09535).
They are the source for `qualify.go` and `behaviors.go`.

**The four qualifier dimensions (intent axes).** Score their co-occurrence, not
any one alone:
- **Surface** (ascending auto-exec severity): vendored/docs/test → runtime →
  import-time (`__init__.py`, `.pth`/`sitecustomize` startup) → build-auto-exec
  (`build.rs`, PKGBUILD `build()`) → install-hook (npm pre/postinstall, `setup.py`
  cmdclass, gemspec, `init.ps1`).
- **Obfuscation** (ascending): none → encoded (base64/hex/zlib/marshal/rot13) →
  string-assembled → dynamic-eval → packed/encrypted (obfuscator.io, PyArmor,
  AES blob, jsfuck, bytecode-only).
- **Exfil/fetch target** (ascending suspicion): reputable-vendor → unknown-domain
  → raw-IP → dynamic-DNS/tunnel → paste/anon-transfer → chat-webhook
  (Discord/Telegram/Slack) → `.onion` → known-bad IOC.
- **Reputation** (amplifier only, never mints alone): established-popular →
  new-maintainer → ownership-change/account-compromise → zero-downloads →
  typosquat.

**The decisive discriminator across every technique: the taint edge** — decoded /
fetched / decrypted / stego'd bytes *reaching* an exec sink (`exec`/`eval`/
`Function`/`compile`/`__import__`/`subprocess`/`child_process`/`chmod +x`). Benign
code uses the same primitives but the decoded output is stored/parsed as **data**,
never executed.

### npm (deep)
| Technique | Malicious behaviour | Benign differentiator |
|-----------|--------------------|------------------------|
| install-lifecycle hook (`pre/postinstall`, **`prepare`** fires on git-install) | hook fetches+executes, decodes→eval, reads secrets, drops OS-branched payload | 94% of malicious npm use install scripts vs ~2.2% of all; benign hooks run **allowlisted** builders (`node-gyp`, `prebuild-install`, `husky`, `patch-package`, `prisma generate`) against the package's own GitHub Releases (pinned + checksummed). |
| remote fetch→eval | response passed to `eval`/`Function`/`vm`/shell; C2 on odd ports (BeaverTail `:1224/pdown`, OtterCookie `eval(r.data.model)`), `*.vercel.app` returning JS | benign fetches a **binary/zip** from a vendor CDN, pinned + checksum-verified (puppeteer, playwright, electron). |
| obfuscation | packing/`_0x`/hex/XOR/AES-blob **with no source map** feeding a decoder→eval | minified bundles ship a `.map` + `sourcesContent` + `/*! @license` + `__webpack_require__`/`__esModule`/`__defProp` and never decode→exec. |
| exfiltration | whole-`process.env` dump, `~/.npmrc`/`~/.ssh`/`~/.aws`/wallet read → chat-webhook/raw-IP/DNS-tunnel/public-GitHub-repo | documented telemetry (anonymous, opt-out, first-party domain); `dotenv.config()` reads into env, never transmits. |
| dependency-confusion / typosquat / starjacking | public name == internal name + inflated semver (`9000.0.0`); Damerau-Levenshtein ≤2 to a popular target; repo `name` ≠ package name | monorepos legitimately share a repo (`@babel/*`, `@aws-sdk/*`); real high versions (React 18); gate name-distance on a reputation red flag. |
| self-propagation (Shai-Hulud) | token read → enumerate maintainer's other packages → mass `npm publish --force`; TruffleHog over `$HOME`; workflow injection | legit release automation publishes **one** package on a CI tag with provenance, reads no other packages' tokens. |
| token-compromise / poisoned tarball | payload only in the published tarball, not the git tag (chalk/debug, event-stream, solana/web3.js) | tarball matches the git tag; provenance attestation chains to the expected repo+workflow. |

### PyPI (deep)
| Technique | Malicious behaviour | Benign differentiator |
|-----------|--------------------|------------------------|
| install-time exec | `cmdclass` override of `install`/`develop`/`egg_info` with body taint; `__import__('builtins').exec`; PEP 517 in-tree malicious backend | overrides only `build_ext`/`build_py`; subprocess targets a named toolchain (`gcc`/`cmake`/`cython`); `build-backend` in the standard allowlist; `super().run()`. |
| import-time / startup | top-level exec in `__init__.py` (ctx, fabrice fire here, **not** install); `.pth`/packaged `sitecustomize.py` whose import line runs `exec` (litellm/TeamPCP) | editable-install `.pth` → `_finder.py` (path-only, never in a published wheel); literal-name lazy imports. |
| obfuscation | nested base64/zlib/marshal (aiocpa 50×), Fernet/PyArmor, bytecode-only `.pyc` (fshec2) → exec | decode→**data** (icons/certs/fixtures); reproducible Cython `.so` from shipped `.pyx`/`.c`. |
| exfiltration | bulk `os.environ` / `~/.aws`/`~/.ssh`/browser/wallet → raw-IP (fabrice `"ht"+"tp"`), Telegram `sendDocument`, Discord webhook, herokuapp | single **named** `os.getenv("MYAPP_X")`; cloud SDK talking only to its provider's own API. |
| typosquat / combosquat / dependency-confusion | homoglyph skeleton match (`jeIlyfish`), affix combosquat, import-name collision, internal-name shadow + v9000 | the real established package; normal install/import mismatches (`pyyaml→yaml`, `Pillow→PIL`); type-stubs/namespace families. |
| multi-stage dropper / native | fetch from raw-IP/paste/dyn-DNS/Discord-CDN → `chmod +x` → exec; PowerShell `-enc`, `certutil -urlcache`; PyInstaller infostealer | runtime model/asset download from reputable, documented, checksum-verified hosts (HuggingFace, torch.hub, NLTK). |
| steganography / artifact mismatch | image/WAV bytes → decode/XOR → exec (apicolor, uwu.png, WAV-stego); file in the sdist/wheel **absent from the matching git tag** (ultralytics, elementary-data) | `Image.open().getdata()` for render/resize (no decode→exec); expected reproducible binary wheels matching build config + attestation. |

### Other ecosystems (templated — same axes)
RubyGems global `Gem.(pre|post)_install_hooks` persistence; Cargo `build.rs`
writing `~/.cargo/config.toml` (registry/credential-helper hijack); NuGet
`init.ps1` reflective `Assembly.Load` + network; Composer lifecycle `curl|bash`;
Maven build-plugin exec; Go has **no** install hook (vector is typosquat +
runtime). Each is recognised by `behaviors.go` and qualified in `qualify.go`.

> Deferred follow-up: a deeper cross-ecosystem research pass (gem/cargo/go/maven/
> nuget/composer/hex/pub/cran/julia) can enrich these rules; the qualifier
> framework above is the reusable template.
