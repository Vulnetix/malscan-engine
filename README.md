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

## Detection model

- A single `evidence` finding marks a package malicious (download-and-execute,
  reverse shells, exfil, GTFObins, a Tor `.onion` C2 source, or an artifact hash
  matching the known-bad set).
- A high-entropy payload is a `trigger`, not standalone evidence — it mints only
  in combination with at least one other distinct trigger (new reporter /
  maintainer / contributor, or a changed maintainer/contributor email). Entropy
  alone never mints; metadata-only combinations never mint.

## Consumers

- `vdb-manager` — `aur-fetch-processor`, `homebrew-fetch-processor` (detection +
  hash check + IOC extraction). Wired via a `replace` directive during local
  development.
- `package-firewall` — loads the `badhash` set (embedded + `MalwareIoc`) to gate
  digest-bearing package requests.
