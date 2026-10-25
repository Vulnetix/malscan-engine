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
2. **The four classes.** `ClassEvidence` mints alone. `ClassTrigger` never mints
   alone — it combines (high-entropy payload + an identity/ownership trigger, or
   ≥2 independent identity families with a change-family). `ClassContext` is
   reputation/risk metadata and never mints. `ClassWeakness` is a **dual-use
   code-execution capability** (`exec(compile(...))`, a shell spawned from a build
   script, `Code.eval_string`): it never mints, never corroborates, and is reported
   downstream as a vulnerability candidate with a CWE and a CVSS vector. It is the
   class for "this code can execute what it is given", as opposed to "this code does
   something hostile".
   - A weakness rule is `weakness = true` in `patterns.toml` with a **required**
     `cwe` and `cvss`; `loadPatterns` panics on a weakness that is also
     `override_gate` or is unscored, so neither can reach production.
   - **Split the capability from the intent, don't pick one.** Keep the broad rule as
     a weakness and add a narrow evidence rule for the hostile shape, each justified
     by a measurement. `P-PY-COMPILE-EXEC` (weakness) / `P-PY-COMPILE-EXEC-DECODED`
     (evidence: the compiled text is decoded, fetched or `_0x…`-named) and
     `P-NPM-HOOK-NODE-EVAL` / `…-EXFIL` (inline hook that reads the host and opens a
     socket) are the worked examples; their comments in `patterns.toml` carry the
     numbers.
   - **A publisher is named only on `ClassEvidence`.** A weakness, a trigger and a
     context finding must never reach an actor-attribution path.
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
   - **Python library text** (`detect/pyview.go`): for pypi `PkgbuildContent`
     with `PkgbuildExecutes=false`, `.py` members other than `setup.py` are read
     with docstrings and `#` comments blanked (offsets and line count kept; not
     when the member reads `__doc__`; never f-strings). Lines that are wholly an
     element of an assigned string-literal list/tuple/set (≥2 strings, no argv
     token such as `sh`/`-c`, never a positional call argument) are context only.
   - **Fidelity** (`Verdict.HighFidelity`): a malicious verdict whose basis is a
     single evidence id from library content (`Finding.Surface == "library"`)
     with no install-script hit is low-fidelity. It still mints; downstream it is
     excluded from automatic approval. It never changes `Malicious`.
   - **Public constants** (`allow/constants.go`): EVM zero/burn addresses,
     canonical USDC/USDT contracts and the secp256k1 n/p are never a wallet
     (`P-CRYPTO-WALLET` suppression, `allow.Benign("wallet", …)`).
   - **An npm hook's file is install code** (`detect/hookfiles.go`). The files a
     `preinstall`/`install`/`postinstall` hook runs with `node` are judged as an
     executing surface (`IS-` prefix, `SurfaceInstall`), so hook_only rules count
     there. `prepare` and `prepublish` do not run on a registry install and are
     ignored. JS-HOOK-DECODE-EGRESS-SEQ and JS-INSTALL-REMOTE-IMPORT read only the
     install hook lines and those files when the processor passes the hooks.
   - **Library content is judged file by file** (`detect/fileview.go`). When
     `PkgbuildExecutes` is false and the content carries the processors' file
     markers, a hit found only in a non-surface file (`nonSurfacePath`: tests,
     testdata, docs, examples, `.github/`, lockfiles and `go.sum`, `vendor/`
     except on packagist, `node_modules/` except on npm, `.yarn/`) is
     `ClassContext` for every rule, override_gate included, and the reported line
     comes from a file that runs. `file_exts` on a rule restricts it to files in its
     language (`.php`, `go.mod`, …); a language rule never judges another language's
     file. Unmarked content is judged whole, as before.
   - **A finding names a line.** A match that crosses a line break is kept only
     for a rule written to span lines (`[\s\S]` in its pattern), and reports the
     line the match starts on. Any other cross-line match is dropped
     (`reportableLine`).
   - **Cargo and NuGet hook rules read the hook only.** `CARGO-CONFIG-PERSISTENCE`
     and `NUGET-ASSEMBLYLOAD-EGRESS` match only install-hook text (`build.rs`,
     nuget install scripts and MSBuild targets), never the whole crate or nupkg.
     A path documented in one file and a write call in another is not persistence.
   - **Command rules need token boundaries.** `P-REVSHELL-NC`, `P-MINER-BINARY`,
     `P-XXD-DECODE` and `P-BASE32` match within one line: `nc` must be a command
     with arguments (`let nc = -c * inv` is not), a miner name is a whole word
     (`gminer` in `logminer` is not), and the decode flag is on the same line.
   - **IOC hits that cannot name a contacted host are context.** `iocscan` keeps a
     known-bad match as `ClassEvidence` only when it can be an endpoint: a hit in a
     comment, a test/fixture/example/doc member (tiered by the processor's
     `==== path ====` separator, demote-only), a data list of five or more literals,
     a zone-file record, or a bare hit on a shared platform front end
     (`allow.SharedHost`) is recorded as `ClassContext`. The shared-host, data-list
     and zone-record demotions never touch a `url` hit. README "What a hit weighs"
     has the detail.
   - **A credential path is not a read.** `P-PASSWD-READ`, `P-SSH-ACCESS` and `P-GPG-ACCESS`
     need a read, copy or send of the literal path on the same line (a reading command,
     `< path`, or a file-open call); `P-SSH-ACCESS` needs a private key, the directory or a glob,
     never a `.pub`, `config` or `known_hosts` path. `P-SUDOERS-MOD` needs a write (redirect,
     `tee`, cp/mv/install/rm/`sed -i`, a write call). Lines inside a test assertion
     (`assert`, `expect(`, `expect_error(`) are suppressed, and so is a sudoers drop-in staged
     under `$pkgdir`.
   - **A printed install hint is not a pipe-to-shell.** `P-CURL-PIPE` needs curl to fetch a URL,
     host, `$var` or `{placeholder}`, and the shell as a whole word (`| shasum` is not). The
     pipe-to-shell family suppresses a line whose command sits inside a string handed to a print,
     log or error call, or is quoted in backticks in a Markdown table row or list item, unless that
     string is redirected (`>`) or piped to a shell.
   - **Backgrounding means a real `&`.** `P-DEVNULL-BACKGROUND`, `P-INSTALL-DEVNULL-BG`,
     `P-NOHUP-BACKGROUND` and `P-INSTALL-NOHUP` need a trailing `&` on the same line that is not
     part of `>&`, `&&` or `&>`. The nohup rules also need a network or payload sign in the nohup
     body (curl/wget/nc/socat, base64, /dev/tcp, `sh -i`, a URL, `python -c`, or a program run
     from /tmp, /var/tmp or /dev/shm); nohup on a dev server or daemon is not a finding.
   - **Recon, cron and clipboard rules need the command.** `P-SYSINFO-RECON`: lspci/dmidecode
     with a flag, pipe or `2>`; `ip addr` in its read form only (never add/del/flush, never the
     prose "ip address"); the command inside a print/log/error string or run through `adb shell`
     is suppressed. `P-CRON-CREATE`/`P-INSTALL-PERSISTENCE`: the crontab command (`-`, `-r`, `-l`,
     a file, a pipe into it, an argv list) or a read/write of a cron path, never the word in a
     parameter name, dependency or tool list. `P-CLIPBOARD-READ`: output mode only (`xclip -o`,
     `xsel -o`, wl-paste/pbpaste at command position); `xclip -selection clipboard`, `xsel -i`,
     wl-copy and pbcopy write the clipboard.
   - **Reverse shells need the shape, on one line.** `P-REVSHELL-DEVTCP`/`P-DEV-UDP` need a shell
     fd redirect into `/dev/tcp/<host>` (`>&`, `<`, `>`, `3<>`), and a line whose every host is
     loopback is suppressed. `P-MKFIFO` needs mkfifo plus nc/ncat/socat/telnet/`openssl s_client`,
     /dev/tcp or `sh -i` (or the `rm /tmp/f;mkfifo /tmp/f` prefix). `G-BUSYBOX-SHELL` needs
     `nc -e`, `telnetd -l sh`, `sh -i` or /dev/tcp; `G-CHOWN-SENSITIVE` ignores chown to root and
     covers .ssh only under /root. Interpreter reverse-shell and GTFOBins rules (`P-REVSHELL-LUA`,
     `-PERL`, `-PYTHON`, `G-REVSHELL-NODE`, `-TCLSH`, `G-VIM-SHELL`, `G-AB-EXFIL`,
     `G-BASENC-DECODE`, `G-ED-SHELL`, `G-GDB-PYTHON`, `P-PRINTF-HEX`, `G-CODE-TUNNEL`) use bounded
     `[^\n]{0,N}` spans and `[ \t]`, never `.*` or `\s`, so a match cannot cross a line or run
     the length of a minified bundle.
   - **Process and command substitution are download-and-execute.** `bash <(curl …)`,
     `source <(curl …)`, `bash -c "$(curl …)"` and `eval "$(curl …)"` are `override_gate`
     (`P-PROC-SUB-EXEC`, `P-CMD-SUB-EXEC` and their `P-INSTALL-` install-script twins). The
     shell must be the command: `cat <(curl …)` and `gpg --verify <(curl …)` read data. In
     library source they are `hook_only` like `P-CURL-PIPE`.
   - **AUR metadata is context unless measured otherwise.** `B-ORPHAN-TAKEOVER` is context.
     `B-TYPOSQUAT` (1 edit) is context when `FirstSubmitted` is ≥ 2 years ago.
     `B-BIN-DOMAIN-MISMATCH` and `T-DIFF-SOURCE-DOMAIN-CHANGED` compare registrable domains
     (`registrableDomain`, a small conservative public-suffix list in `binsource.go`, no
     dependency); GitHub hosts compare by repository owner. `T-DIFF-CHECKSUM-REMOVED` needs a
     remaining non-VCS source a checksum could pin.
   - **Unverified-download and privilege-config shapes are weaknesses.** `P-HTTP-SOURCE-SKIP`
     and `JL-BUILD-UNVERIFIED-DOWNLOAD` (CWE-494), `P-SUDOERS-WEAK-GRANT` (CWE-269),
     `P-LD-SO-PRELOAD` (CWE-829). They never mint.
   - **PKGBUILD-family line judgements** live in `detect/pkgbuild_lines.go`
     (`suppressPkgbuildLine`: metadata assignments, eval position, sudoers parsing, a miner the
     package is named after, a formula's own library path, Julia build fetches;
     `homebrewExecView`: caveats, `test do` and message text; `installTopLevelCommands`: commands
     outside every .install hook). The shell judgements apply only to shell recipes (AUR,
     APKBUILD), never to a quoted npm or Ruby command string.
   - **Injection and persistence rules need the act, not the name.** `P-LD-PRELOAD` needs
     LD_PRELOAD set at command position to a library in /tmp, /var/tmp, /dev/shm or $TMPDIR (a
     sanitizer, fakeroot or jemalloc preload is not injection). `P-PROMPT-COMMAND` and
     `P-ALIAS-OVERRIDE` need the hook or alias written into a shell rc file on the same line, or a
     body that fetches or decodes; a printed shell-integration snippet is a feature.
     `P-XDG-AUTOSTART` needs a write (redirect, `tee`, cp/mv/install/ln, a write call) into
     `.config/autostart`; `P-UDEV-RULE` needs `RUN+=` with the rules path. `P-AT-JOB` needs the
     job's input on the line (a pipe into `at TIME`, `at -f`, a heredoc or `<`, an argv list).
     `G-SYSTEMD-RUN` needs a shell (`-t`/`--pty`, `sh -i`) or a payload (curl/wget/nc/socat,
     /dev/tcp, `base64 -d`, a program in /tmp) in the transient unit.
   - **Writing a log is not clearing it.** `P-LOG-CLEAR` needs rm of /var/log, `/var/log/*` or a
     system log (auth, syslog, wtmp, audit, ...), truncate of a /var/log path, or a standalone
     truncating `>` at command position (`> /var/log/wtmp`, `cat /dev/null > ...`); `>>`, `2>`,
     `&>`, `cmd > /var/log/x.log 2>&1` and plist `<string>` paths are logging. `P-HISTORY-CLEAR`
     needs `history -c` as a command; `HISTFILE=/dev/null`, `unset HISTFILE` and `set +o history`
     keep a tool's own driven shell out of the user's history and are not findings.
   - **An encoded payload is decoded and run.** `P-OCTAL-ENCODE` needs four or more consecutive
     octal escapes of printable ASCII (never `\033[` colours, `\000` separators, file magic or
     UTF-8 bytes) in a printf/`echo -e` that runs: inside `$(...)`, backquotes or eval, or piped to
     a shell. `P-REV-EXEC` needs `rev` as a command piped to a shell on the same line.
     `P-JS-CHILDPROC-DECODE` needs exec/execSync/execFile/spawn called (not RegExp `.exec(`, not a
     test mock) with `Buffer.from(x, 'base64'|'hex')` or `atob(` in its arguments; `.toString('base64')`
     encodes.
6. **goodkeys first.** Actor-key enrichment must call `goodkeys` before any
   DB/registry/GitHub lookup — a web-merged commit is signed by GitHub, not the
   attacker.
7. **Allowlist stays conservative.** Only unambiguously non-indicative values go
   in `allow`; never allowlist something that could be a real C2/exfil host.
   - Operator-run DNS infrastructure is listed by address: public resolvers, the
     root and gTLD servers, AliDNS's two anycast /24s, and the RFC 4892 CHAOS
     names (`version.bind`, `id.server`, …). So are vendor-only hosts that no third
     party can publish under (`api.adoptium.net`, `dl.google.com`, LLM provider
     APIs). A platform that serves user content (`claude.ai`, `workers.dev`,
     `trycloudflare.com`, `pastebin.com`, `webhook.site`, `raw.githubusercontent.com`
     URLs) is never allowlisted.
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
hooks exist; `bad-actor-behaviors` only npm/pypi/rubygems/cargo/nuget/go, whose
registry-native TTPs the detector recognises; for go, an `init()` that registers
HTTP handlers in a file where request values reach `exec.Command`).

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
