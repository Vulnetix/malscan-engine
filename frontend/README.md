# malscan-frontend

A native ([egui]/[eframe]) configuration frontend for the Vulnetix
`malscan-engine`. It exposes the engine's detection surface as a per-ecosystem
settings panel:

- An **ecosystem switcher** (top-right) listing exactly the registries the engine
  recognises — `aur`, `homebrew`, `npm`, `pypi`, `rubygems`, `go`, `cargo`,
  `nuget` (the slugs from `detect/model.go`, `PackageContext.Ecosystem`).
- For the selected ecosystem, an **Overview** tab that:
  - shows only the engine capabilities that ecosystem *supports* (the support
    matrix is grounded in the Go source — e.g. `-bin` source verification and
    registry-comment scanning are AUR-only; Go/Cargo have no install-hook stage),
    each with an **on/off toggle** and a colour-coded class chip
    (`evidence` / `trigger` / `context` / `module`);
  - lets you edit the ecosystem's **registry endpoint**.
- A **Config (JSON)** tab previewing the exact file that is persisted.
- A **Save** button that writes the ecosystem's committed default
  (`config/defaults/<slug>.json`) — the file the **Go engine embeds** and reads
  to short-circuit detectors a human disabled (see below). Pushing the same
  document to a remote backend is the one remaining stub (`TODO(api)` in
  `src/api.rs`); local file persistence is real.

## Configuration & the engine

This app manages the **committed repo defaults** — `config/defaults/<slug>.json`
at the repo root, one JSON document per ecosystem. It loads them on startup and
rewrites the relevant file on save (so saving edits the version-controlled file).
The defaults directory is `MALSCAN_DEFAULTS_DIR` if set, else `<repo>/config/defaults`
(resolved relative to this crate). Regenerate the full set with `just gen-defaults`.

```json
{
  "ecosystem": "npm",
  "registry_endpoint": "https://registry.npmjs.org",
  "capabilities": { "manifest-patterns": true, "checksum": false }
}
```

The Go engine **embeds** these defaults (`//go:embed defaults/*.json`) and, at
runtime, overlays any operator **override** files from the system config dir
(`MALSCAN_CONFIG_DIR` / `os.UserConfigDir`) — which this app does *not* touch.
`detect.Detect` then skips any detector resolved to `false`. A missing file or
absent key means *enabled*. See the root README, "Configuration: how the Go
modules read it", for the full merge semantics. In short:

```go
ec, _ := config.ResolveDefault("npm")          // embedded default ⊕ system override
ctx := &detect.PackageContext{ /* … */ Capabilities: ec.Capabilities}
findings := detect.Detect(ctx)                 // disabled detectors are short-circuited
```

## Keyboard

A status bar at the bottom lists the shortcuts. They are active unless a text
field (the endpoint or jump box) has focus:

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move the capability selection cursor (the highlighted row) |
| `Space` / `Enter` | Toggle the selected capability |
| `←` / `→` | Cycle ecosystem (previous / next) |
| `Tab` / `Shift+Tab` | Switch view (Overview ↔ Config JSON) |
| `A` | Toggle all capabilities for the current ecosystem |
| `/` | Open the jump box — type an ecosystem name/slug to live-select it; `Enter` commits, `Esc` restores the prior selection |

Shortcuts are read with egui's `consume_key`, so they don't also fire egui's
own defaults (e.g. `Tab` moving widget focus). The mouse still works for
everything; clicking a capability also moves the selection cursor to it.

## Run

Dev tasks go through [`just`](https://github.com/casey/just) — run `just` from
the repo root to list recipes:

```sh
just run         # launch the egui frontend
just build       # debug build
just release     # release build
just check       # fmt-check + clippy + tests (Rust) and vet + tests (Go)
```

Or directly with cargo:

```sh
cd frontend
cargo run
```

> The crate disables eframe's default features and keeps only
> `default_fonts`, `glow`, `wayland`, `x11` — this drops the Linux
> `accesskit → zbus` accessibility stack (not needed here, and a flaky fetch on
> the Vulnetix cargo mirror).

## Test

```sh
just test        # or: cd frontend && cargo test
```

Headless tests cover the per-ecosystem support-matrix counts, default config
generation (all supported capabilities enabled), endpoint reset, and JSON
round-tripping.

## Layout

| File | Responsibility |
|------|----------------|
| `src/model.rs` | The engine model mirrored for the UI: `ECOSYSTEMS` and the `CAPABILITIES` catalog (each capability names the Go symbol / signal-id family it maps to, plus its per-ecosystem `Support`). |
| `src/config.rs` | Editable, serialisable per-ecosystem settings (endpoint + capability enable map). Defaults derive from the catalog. |
| `src/api.rs` | Stub persistence API — builds the save request; `TODO(api)` marks where to wire the real backend call. |
| `src/app.rs` | The egui app: ecosystem switcher, tab strip, Overview + Config-JSON tabs. |
| `src/main.rs` | eframe entry point. |

## Relationship to the engine

This crate is a **frontend only** — it does not invoke the Go engine. It mirrors
the engine's detector set so settings can be authored and (eventually) saved.
When the engine adds or moves a detector, update `CAPABILITIES` in
`src/model.rs`; the `support_matrix_matches_engine` test guards the counts
against accidental drift.

[egui]: https://github.com/emilk/egui
[eframe]: https://github.com/emilk/egui/tree/main/crates/eframe
