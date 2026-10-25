package detect

import (
	"path"
	"regexp"
	"strings"
)

// An npm lifecycle hook is usually one command, `node install.js`, and the code that runs at
// install time is the file it names. The npm processor passes the hook command lines as
// InstallScriptContent and the tarball's files as PkgbuildContent, so without this the engine
// judged the hook file as library content: hook_only rules were demoted in the one file that
// auto-executes. metrics-probe-9b4c 1.0.0 (GCVE-110-NPM-2026-033137, missed by the scanner and
// confirmed in the 2026-10-25 audit) is `preinstall: node run.js`, where run.js bypasses UAC and
// uploads Windows credentials.
var npmHookNodeRe = regexp.MustCompile(`\bnode(?:\.exe)?[ \t]+(?:-[-\w]+(?:=\S+)?[ \t]+)*["']?((?:\./)?[\w@./-]+\.[cm]?js)\b`)

// npmHookImportRe is a local module an inline hook loads: `node -e "import('./src/agent.js').then(…)"`,
// `node -e "require('./lib/setup')"`. iobend 2.6.4 (GCVE-110-NPM-2026-033894, kept as malware in the
// 2026-10-25 audit) installs a login-persistent agent daemon this way, from src/services/agentDaemon.js.
var npmHookImportRe = regexp.MustCompile("\\b(?:import|require)\\(\\s*\\\\?[\"'`]((?:\\.{1,2}/)[\\w@./-]+?)(?:\\.([cm]?js))?\\\\?[\"'`]")

var (
	npmScriptKeyRe  = regexp.MustCompile(`^[\w:-]+$`)
	npmInstallHooks = map[string]bool{"preinstall": true, "install": true, "postinstall": true}
)

// npmHookFiles returns the bodies of the package files that npm lifecycle hooks run with node,
// joined, or "" when there are none (or the content carries no file markers to find them by).
func npmHookFiles(ctx *PackageContext) string {
	if !strings.EqualFold(strings.TrimSpace(ctx.Ecosystem), "npm") || ctx.InstallScriptContent == "" {
		return ""
	}
	fi := newFileIndex(ctx.PkgbuildContent, ctx.Ecosystem)
	if fi == nil {
		return ""
	}
	want := map[string]bool{}
	// Only the install hooks run when a consumer installs from the registry; prepare and
	// prepublish run in the package's own checkout.
	install := npmInstallLines(ctx.InstallScriptContent)
	for _, m := range npmHookNodeRe.FindAllStringSubmatch(install, -1) {
		want[path.Clean(m[1])] = true
	}
	for _, m := range npmHookImportRe.FindAllStringSubmatch(install, -1) {
		if m[2] != "" {
			want[path.Clean(m[1]+"."+m[2])] = true
			continue
		}
		for _, ext := range []string{".js", ".cjs", ".mjs", "/index.js"} {
			want[path.Clean(m[1]+ext)] = true
		}
	}
	if len(want) == 0 {
		return ""
	}
	lines := strings.Split(ctx.PkgbuildContent, "\n")
	var b strings.Builder
	for _, s := range fi.segs {
		// Tarball entries are "package/<path>"; a hook names the path relative to the package root.
		rel := strings.ReplaceAll(s.path, `\`, "/")
		if i := strings.IndexByte(rel, '/'); i >= 0 {
			rel = rel[i+1:]
		}
		if !want[path.Clean(rel)] {
			continue
		}
		b.WriteString(strings.Join(lines[s.start:s.end], "\n"))
		b.WriteString("\n")
	}
	return b.String()
}

// npmInstallLines returns the preinstall, install and postinstall lines of the processor's
// "<hook>: <command>" hook text. Text not in that shape is returned whole.
func npmInstallLines(hooks string) string {
	var b strings.Builder
	for _, line := range strings.Split(hooks, "\n") {
		if k, _, ok := strings.Cut(line, ": "); ok && npmScriptKeyRe.MatchString(k) && !npmInstallHooks[k] {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
