package detect

import (
	"regexp"
	"strings"
)

// analyzeBadActorBehaviors detects multi-line, registry-native supply-chain
// TTPs that the single-line pattern database (patterns.toml) cannot capture:
// sequences (lifecycle hook + decode + network), global install-hook
// persistence, .pth auto-import persistence, and credential-file reads inside a
// build/install surface. Each finding carries its Qualification (intent +
// behaviour + benign-vs-malicious differentiator) in the Description so the
// advisory explains WHY the usage is malicious — the intent of the usage is the
// differentiator the engine records.
//
// Sources for the encoded behaviours: OpenSSF/OSV malicious-package advisories,
// Socket/Aqua/Snyk supply-chain write-ups, MITRE ATT&CK. Only behaviours with an
// unambiguous benign-vs-malicious differentiator are emitted as ClassEvidence;
// sequence findings that need a compounding signal are ClassTrigger/ClassContext.
//
// It is gated by CapBadActorBehaviors and runs over both the manifest
// (PkgbuildContent) and install hooks (InstallScriptContent), since these TTPs
// are ecosystem-native (npm lifecycle, Python setup.py, Ruby gemspec, Rust
// build.rs) rather than shell-specific.
func analyzeBadActorBehaviors(ctx *PackageContext) []Finding {
	if ctx == nil {
		return nil
	}
	var out []Finding
	manifest := ctx.PkgbuildContent
	hooks := ctx.InstallScriptContent
	combined := manifest
	if hooks != "" {
		if combined != "" {
			combined += "\n"
		}
		combined += hooks
	}
	if combined == "" {
		return nil
	}
	eco := strings.ToLower(ctx.Ecosystem)

	// ── RubyGems: global Gem.post_install_hooks persistence ──────────────────
	// A gem registering Gem.post_install_hooks (or Gem.pre_install_hooks) runs
	// arbitrary code on EVERY future gem install once it is loaded. This is a
	// documented RubyGems supply-chain persistence TTP (e.g. the "bigdecimal"
	// / "rdoc" typosquat campaigns). There is no benign reason for a published
	// gem to register a GLOBAL install hook — the API exists for installers and
	// tooling, not for gems. Intent: persistence → ClassEvidence.
	if eco == "rubygems" || eco == "gem" || eco == "" {
		if gemPostInstallHookRE.MatchString(combined) {
			out = append(out, qualifiedEvidence(
				"GEM-GLOBAL-INSTALL-HOOK",
				"behavioral",
				"RubyGems global Gem.post_install_hooks persistence: the gem registers a hook that runs on every future gem install (documented supply-chain persistence TTP). Benign gems never register a global install hook — the API is for installers/tooling, not published gems.",
			))
		}
	}

	// ── Python: .pth auto-import persistence in setup.py ─────────────────────
	// A .pth file in site-packages whose line starts with "import " is auto-run
	// by Python at interpreter start — a documented PyPI persistence TTP. A
	// package whose setup.py/install writes a .pth file carrying executable
	// content is establishing persistence. Benign .pth files only append paths
	// (no "import"). Intent: persistence → ClassEvidence.
	if eco == "pypi" || eco == "python" || eco == "" {
		if pthExecutableWriteRE.MatchString(combined) {
			out = append(out, qualifiedEvidence(
				"PY-PTH-AUTOIMPORT-PERSISTENCE",
				"behavioral",
				"setup.py writes a .pth file containing executable import code: Python auto-runs .pth lines starting with 'import' at interpreter start (documented PyPI persistence TTP). Benign .pth files only append to sys.path — they never carry import statements.",
			))
		}
	}

	// ── npm: lifecycle hook + decode + network egress sequence ───────────────
	// The #1 documented npm supply-chain TTP: a preinstall/postinstall hook that
	// decodes a payload (atob/Buffer.from) AND contacts the network. Single-regex
	// rules catch each atom; this detector captures the SEQUENCE in one finding
	// so the advisory states the intent (exfiltration/staged execution). Emitted
	// as ClassTrigger so it corroborates the combination gate rather than
	// double-minting; the gate already mints on the override-gate atoms.
	if (eco == "npm" || eco == "node" || eco == "") && hasInstallHook(manifest) {
		if npmDecodeRE.MatchString(combined) && npmNetEgressRE.MatchString(combined) {
			out = append(out, qualifiedTrigger(
				"JS-HOOK-DECODE-EGRESS-SEQ",
				"behavioral",
				"npm lifecycle hook decodes a payload (atob/Buffer.from) AND opens a network egress: the canonical npm install-time exfiltration/staged-execution sequence. A benign hook may decode an asset OR contact a registry, but decode+egress together in an install hook is exfiltration/staging.",
			))
		}
		// npm install hook that require()/import from a remote https URL bypasses
		// the registry and fetches attacker-controlled code at install time.
		if npmRemoteImportRE.MatchString(combined) {
			out = append(out, qualifiedEvidence(
				"JS-INSTALL-REMOTE-IMPORT",
				"behavioral",
				"npm lifecycle hook require()/imports from a remote https URL: the hook fetches attacker-controlled code outside the registry at install time. Benign packages declare dependencies in package.json and load them from the registry; an install hook that loads a remote URL is a download-and-execute bypass.",
			))
		}
	}

	// ── PyPI: setup.py reads a credential file AND egresses ──────────────────
	// Documented PyPI typosquat TTP: setup.py opens ~/.aws/credentials,
	// ~/.ssh/id_rsa, or ~/.docker/config.json and POSTs the contents. Reading a
	// credential path in setup.py is already strong; pairing it with a network
	// call is exfiltration. Intent: exfiltration → ClassEvidence.
	if eco == "pypi" || eco == "python" || eco == "" {
		if pyCredFileRE.MatchString(combined) && pyNetEgressRE.MatchString(combined) {
			out = append(out, qualifiedEvidence(
				"PY-SETUP-CRED-EXFIL",
				"behavioral",
				"setup.py opens a credential file (~/.aws/credentials, ~/.ssh/id_rsa, ~/.docker/config.json, ~/.netrc) AND contacts the network: documented PyPI credential-exfiltration TTP. A benign setup.py never reads credential stores; reading one AND egressing is theft.",
			))
		}
		// setup.py dynamic module load + exec/compile: a common obfuscation TTP
		// that hides the payload in a separately-fetched or embedded module.
		if pyImportlibExecRE.MatchString(combined) {
			out = append(out, qualifiedEvidence(
				"PY-SETUP-IMPORTLIB-EXEC",
				"behavioral",
				"setup.py uses importlib/imp to load a module and immediately exec/compile/eval it: documented PyPI obfuscated-execution TTP. Benign setup.py imports pinned dependencies plainly; dynamic module load + exec at install time is a staged payload.",
			))
		}
	}

	// ── Cargo: build.rs persists a cargo config credential override ───────────
	// Documented Rust supply-chain TTP: build.rs writes ~/.cargo/config.toml to
	// install a credential helper / replace the registry / set
	// git-fetch-with-cli — persisting across builds and hijacking future
	// dependency fetches. Benign build.rs never rewrites the global cargo
	// config. Intent: persistence → ClassEvidence.
	if eco == "cargo" || eco == "rust" || eco == "" {
		if cargoConfigPathRE.MatchString(combined) && cargoWriteCallRE.MatchString(combined) {
			out = append(out, qualifiedEvidence(
				"CARGO-CONFIG-PERSISTENCE",
				"behavioral",
				"build.rs writes the global ~/.cargo/config.toml (or .cargo/config.toml): documented Rust supply-chain persistence TTP — a malicious build script installs a credential helper or replaces the registry to hijack future fetches. Benign build.rs never rewrites the cargo config.",
			))
		}
	}

	// ── NuGet: init.ps1 / install.ps1 Assembly.Load + network ─────────────────
	// Documented NuGet TTP: an install hook that reflectively loads an assembly
	// (Assembly.Load) and contacts the network. Benign install hooks only
	// copy/reference project files; reflective load + network is staged
	// execution/exfil. Intent: malicious → ClassEvidence.
	if eco == "nuget" || eco == "dotnet" || eco == "" {
		if nugetAssemblyLoadRE.MatchString(combined) && nugetNetEgressRE.MatchString(combined) {
			out = append(out, qualifiedEvidence(
				"NUGET-ASSEMBLYLOAD-EGRESS",
				"behavioral",
				"NuGet install hook reflectively loads an assembly (Assembly.Load/LoadFrom) AND contacts the network: documented NuGet staged-execution/exfil TTP. A benign init.ps1 only sets up project references; reflective load + network from an install hook is malicious.",
			))
		}
	}

	return out
}

// qualifiedEvidence builds a ClassEvidence finding whose Description carries
// the full qualification (intent + behaviour + differentiator). The structured
// Qualification is also retrievable via Qualify() by signal id.
func qualifiedEvidence(id, category, desc string) Finding {
	return Finding{
		ID:          id,
		Category:    category,
		Class:       ClassEvidence,
		CWE:         cweForSignal(id),
		Description: desc,
	}
}

// qualifiedTrigger builds a ClassTrigger finding (corroboration; combines via
// the combination gate) with a qualifying description.
func qualifiedTrigger(id, category, desc string) Finding {
	return Finding{
		ID:          id,
		Category:    category,
		Class:       ClassTrigger,
		CWE:         cweForSignal(id),
		Description: desc,
	}
}

// installHookNames are the npm lifecycle scripts that auto-run at install/
// package time, i.e. the actual malware execution surface. Dev/test/version
// scripts (build, test, postversion, etc.) operate on explicit user action and
// must not trigger install-time detectors.
var installHookNames = []string{
	"\"preinstall\"", "'preinstall'",
	"\"install\"", "'install'",
	"\"postinstall\"", "'postinstall'",
	"\"preprepare\"", "'preprepare'",
	"\"prepare\"", "'prepare'",
	"\"postprepare\"", "'postprepare'",
	"\"prepublishOnly\"", "'prepublishOnly'",
}

// hasLifecycleHook reports whether the npm manifest text declares any lifecycle
// script (including dev/test/version scripts). Kept for callers that want the
// broad definition.
func hasLifecycleHook(manifest string) bool {
	for _, k := range []string{"\"preinstall\"", "'preinstall'",
		"\"postinstall\"", "'postinstall'", "\"install\"", "'install'",
		"\"prepare\"", "'prepare'", "\"preprepare\"", "'preprepare'",
		"\"postprepare\"", "'postprepare'", "\"prepublishOnly\"", "'prepublishOnly'",
		"\"preversion\"", "'preversion'", "\"version\"", "'version'",
		"\"postversion\"", "'postversion'", "\"pretest\"", "'pretest'",
		"\"test\"", "'test'", "\"posttest\"", "'posttest'",
		"\"prebuild\"", "'prebuild'", "\"build\"", "'build'", "\"postbuild\"", "'postbuild'",
		"\"prestart\"", "'prestart'", "\"start\"", "'start'", "\"poststart\"", "'poststart'"} {
		if strings.Contains(manifest, k) {
			return true
		}
	}
	return false
}

// hasInstallHook reports whether the npm manifest text declares an install-time
// lifecycle hook (preinstall/install/postinstall/prepare/prepublishOnly). This
// is the narrower gate used by behavioral detectors that only make sense when
// code runs automatically during `npm install`.
func hasInstallHook(manifest string) bool {
	for _, k := range installHookNames {
		if strings.Contains(manifest, k) {
			return true
		}
	}
	return false
}

// ── behaviour regexes ────────────────────────────────────────────────────────
//
// These are intentionally anchored to the malicious SHAPE of each TTP, not the
// benign primitives, so they carry the intent directly:
//   - Gem.post_install_hooks (plural, the global registry) — not the benign
//     per-gem .install hook.
//   - a .pth WRITE carrying an "import " line — not a path-only .pth.
//   - decode + egress together in a lifecycle hook — not either alone.
//   - a credential-file PATH opened + network — not a generic open().

var (
	gemPostInstallHookRE = regexp.MustCompile(`Gem\.(pre|post)_install_hooks\s*(?:<<|\.push|\.unshift)`)

	// A .pth file write carrying executable import code on the same line. RE2
	// has no backreferences, so we match a single line that contains BOTH a .pth
	// path and an import stem (either order). A benign .pth only appends a path.
	pthExecutableWriteRE = regexp.MustCompile(`(?m)^[^\n]*\.pth[^\n]*\bimport\b|^[^\n]*\bimport\b[^\n]*\.pth`)

	npmDecodeRE    = regexp.MustCompile(`(?:atob|Buffer\.from)\s*\(`)
	npmNetEgressRE = regexp.MustCompile(`(?:https?://|fetch\s*\(|net\.(connect|createConnection|Socket)|http\.(get|request)|dgram\.|dns\.)`)
	// require('https://...') or import('https://...') or import x from 'https://...'
	npmRemoteImportRE = regexp.MustCompile(`(?i)(?:require|import)\s*\(\s*['"]https?://|import\s+[^'"]*['"]https?://`)

	pyCredFileRE  = regexp.MustCompile(`(?:~/\.aws/credentials|~/\.ssh/id_(?:rsa|ed25519|ecdsa)|~/\.docker/config\.json|~/\.netrc|~/\.pypirc)`)
	pyNetEgressRE = regexp.MustCompile(`(?:urllib\.request\.urlopen|requests\.(?:post|get|put)|httpx\.(?:post|get|Client)|urlopen|socket\.connect)`)
	pyImportlibExecRE = regexp.MustCompile(`(?i)(?:importlib|imp\b)[\s\S]{0,120}(?:exec(?:_module)?\s*\(|compile\s*\(|eval\s*\()`)

	// A cargo config path AND a write call. They may appear in either order
	// (fs::write(path, …) or path = …; fs::write), so two separate regexes both
	// must match rather than one ordered pattern.
	cargoConfigPathRE = regexp.MustCompile(`\.cargo[/\\]config(?:\.toml)?`)
	cargoWriteCallRE  = regexp.MustCompile(`(?:fs::write|\.write\s*\(|OpenOptions|File::create|write_to_path)`)

	nugetAssemblyLoadRE = regexp.MustCompile(`(?i)\[System\.Reflection\.Assembly\]::Load|Assembly\.Load(?:From|File)?\s*\(`)
	nugetNetEgressRE    = regexp.MustCompile(`(?i)(?:Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|System\.Net\.WebClient|HttpClient)`)
)
