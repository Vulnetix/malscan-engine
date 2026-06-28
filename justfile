# malscan-engine dev tasks — run `just` (or `just --list`) to see recipes.
# Frontend recipes run inside ./frontend; engine recipes run at the repo root.

# List available recipes
default:
    @just --list

# ── Rust frontend ───────────────────────────────────────────────────────────

# Launch the egui configuration frontend
[group('frontend')]
[working-directory: 'frontend']
run:
    cargo run

# Build the frontend (debug)
[group('frontend')]
[working-directory: 'frontend']
build:
    cargo build

# Build the frontend (release)
[group('frontend')]
[working-directory: 'frontend']
release:
    cargo build --release

# Run the frontend tests
[group('frontend')]
[working-directory: 'frontend']
test:
    cargo test

# Regenerate the committed repo defaults (config/defaults/*.json)
[group('frontend')]
[working-directory: 'frontend']
gen-defaults:
    cargo run -- --write-defaults

# Lint with clippy (warnings are errors)
[group('frontend')]
[working-directory: 'frontend']
clippy:
    cargo clippy --all-targets -- -D warnings

# Format Rust sources
[group('frontend')]
[working-directory: 'frontend']
fmt:
    cargo fmt

# Check Rust formatting without writing changes
[group('frontend')]
[working-directory: 'frontend']
fmt-check:
    cargo fmt --check

# Remove the Rust build artifacts
[group('frontend')]
[working-directory: 'frontend']
clean:
    cargo clean

# ── Go engine ───────────────────────────────────────────────────────────────

# Run the Go engine tests
[group('engine')]
go-test:
    go test ./...

# Vet the Go engine
[group('engine')]
go-vet:
    go vet ./...

# Build the Go packages
[group('engine')]
go-build:
    go build ./...

# ── Threat-intel blocklists (badnet) ─────────────────────────────────────────

# Refresh the embedded bad-IP/host/email blocklists from public feeds (stale-guarded)
[group('engine')]
gen-blocklists:
    go run ./cmd/genblocklist

# Force-refresh the embedded blocklists, ignoring the freshness check
[group('engine')]
gen-blocklists-force:
    go run ./cmd/genblocklist --force

# Install the version-controlled git hooks (sets core.hooksPath to .githooks)
[group('engine')]
install-hooks:
    chmod +x .githooks/* 2>/dev/null || true
    git config core.hooksPath .githooks
    @echo "git hooks installed (core.hooksPath=.githooks)"

# ── Aggregate ───────────────────────────────────────────────────────────────

# Full CI-style gate: format check, lint, and tests across Rust + Go
check: fmt-check clippy test go-vet go-test
