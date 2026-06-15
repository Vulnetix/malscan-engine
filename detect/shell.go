package detect

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Shell-obfuscation analysis — port of traur src/features/shell_analysis/mod.rs.
// Detects download-and-execute and dangerous commands assembled via variable
// concatenation, indirect execution, char-by-char construction, encoded data
// blobs, high-entropy heredocs, and download+chmod-without-compile. All shell
// findings are factual malicious evidence.

var pkgbuildStandardVars = map[string]bool{
	"pkgname": true, "pkgver": true, "pkgrel": true, "epoch": true, "pkgdesc": true,
	"arch": true, "url": true, "license": true, "groups": true, "depends": true,
	"makedepends": true, "checkdepends": true, "optdepends": true, "provides": true,
	"conflicts": true, "replaces": true, "backup": true, "options": true, "install": true,
	"changelog": true, "source": true, "noextract": true, "md5sums": true, "sha1sums": true,
	"sha224sums": true, "sha256sums": true, "sha384sums": true, "sha512sums": true,
	"b2sums": true, "validpgpkeys": true,
	"CFLAGS": true, "CXXFLAGS": true, "CPPFLAGS": true, "LDFLAGS": true, "GOFLAGS": true,
	"CGO_CFLAGS": true, "CGO_CPPFLAGS": true, "CGO_CXXFLAGS": true, "CGO_LDFLAGS": true,
	"MAKEFLAGS": true, "srcdir": true, "pkgdir": true, "startdir": true,
}

var dangerousCommands = []string{
	"curl", "wget", "nc", "ncat", "bash", "sh", "python", "python3", "python2",
	"perl", "ruby", "php", "lua", "socat", "telnet",
}

var dangerousPipes = [][2]string{
	{"curl", "bash"}, {"curl", "sh"}, {"curl", "python"}, {"curl", "python3"},
	{"wget", "bash"}, {"wget", "sh"}, {"wget", "python"}, {"wget", "python3"},
}

var buildCommands = []string{
	"make", "cmake", "cargo", "gcc", "g++", "go build", "go install", "rustc",
	"javac", "mvn", "gradle", "meson", "ninja", "configure", "python setup.py",
	"pip install", "npm run build", "yarn build", "qmake", "scons", "waf",
}

var (
	assignRE          = regexp.MustCompile(`(?:^|;)\s*([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|([^;"'\s]*))`)
	varRefRE          = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	printfSubshellRE  = regexp.MustCompile(`\$\(\s*printf\s+['"]?\\+(x[0-9a-fA-F]{2}|[0-7]{3})['"]?\s*\)`)
	echoSubshellRE    = regexp.MustCompile(`\$\(\s*echo\s+-[neE]+\s+['"]?\\+(x[0-9a-fA-F]{2}|[0-7]{3})['"]?\s*\)`)
	longHexRE         = regexp.MustCompile(`[0-9a-fA-F]{129,}`)
	checksumLineRE    = regexp.MustCompile(`(?i)(md5|sha\d+|b2)sums`)
	checksumArrayOpen = regexp.MustCompile(`(?i)(md5|sha\d+|b2)sums(_[a-zA-Z0-9_]+)?\s*=\s*\(`)
	longBase64RE      = regexp.MustCompile(`[A-Za-z0-9+/]{100,}={0,3}`)
	heredocStartRE    = regexp.MustCompile(`<<-?\s*['"]?(\w+)['"]?`)
	downloadToFileRE  = regexp.MustCompile(`(curl\s+.*-[oO]\s|wget\s+.*-O\s|curl\s+.*>\s)`)
	chmodExecRE       = regexp.MustCompile(`chmod\s+\+x\s`)
)

// analyzeShell runs all shell sub-analyzers over content. idPrefix/descSuffix
// distinguish install-script findings ("IS-" prefix).
func analyzeShell(content, idPrefix, descSuffix string) []Finding {
	env := buildVarEnv(content)
	var out []Finding
	out = append(out, analyzeVariableResolution(content, env)...)
	out = append(out, analyzeIndirectExecution(content, env)...)
	out = append(out, analyzeCharByCharConstruction(content)...)
	out = append(out, analyzeDataBlobs(content)...)
	out = append(out, analyzeBinaryDownload(content)...)

	if idPrefix != "" || descSuffix != "" {
		for i := range out {
			out[i].ID = idPrefix + out[i].ID
			if descSuffix != "" {
				out[i].Description = out[i].Description + " " + descSuffix
			}
		}
	}
	for i := range out {
		out[i].Category = "shell"
		// Preserve a class already set by the sub-analyzer (the high-entropy
		// heredoc is a ClassTrigger, not standalone evidence); default the rest
		// to evidence.
		if out[i].Class == "" {
			out[i].Class = ClassEvidence
		}
		out[i].CWE = cweForSignal(out[i].ID)
	}
	return out
}

func buildVarEnv(content string) map[string]string {
	env := map[string]string{}
	for _, line := range splitLines(content) {
		for _, caps := range assignRE.FindAllStringSubmatch(line, -1) {
			name := caps[1]
			if pkgbuildStandardVars[name] {
				continue
			}
			val := caps[2]
			if val == "" {
				val = caps[3]
			}
			if val == "" {
				val = caps[4]
			}
			env[name] = val
		}
	}
	return env
}

func resolveVariables(line string, env map[string]string) string {
	return varRefRE.ReplaceAllStringFunc(line, func(m string) string {
		sub := varRefRE.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		if v, ok := env[sub[1]]; ok {
			return v
		}
		return m
	})
}

func containsDangerousPipe(resolved string) (string, string, bool) {
	lower := strings.ToLower(resolved)
	if !strings.Contains(lower, "|") {
		return "", "", false
	}
	parts := strings.Split(lower, "|")
	for i := 0; i < len(parts)-1; i++ {
		left := strings.TrimSpace(parts[i])
		right := strings.TrimSpace(parts[i+1])
		for _, dp := range dangerousPipes {
			if strings.Contains(left, dp[0]) && strings.Contains(right, dp[1]) {
				return dp[0], dp[1], true
			}
		}
	}
	return "", "", false
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// hasWordMatch reports whether word appears in text at a word boundary.
func hasWordMatch(text, word string) bool {
	start := 0
	for {
		idx := strings.Index(text[start:], word)
		if idx < 0 {
			return false
		}
		abs := start + idx
		beforeOK := abs == 0 || !isWordChar(text[abs-1])
		end := abs + len(word)
		afterOK := end >= len(text) || !isWordChar(text[end])
		if beforeOK && afterOK {
			return true
		}
		start = abs + 1
	}
}

func containsMultiVarDangerousCmd(original, resolved string, env map[string]string) (string, bool) {
	origLower := strings.ToLower(original)
	resLower := strings.ToLower(resolved)
	for _, cmd := range dangerousCommands {
		if !hasWordMatch(resLower, cmd) || hasWordMatch(origLower, cmd) {
			continue
		}
		singleVarHoldsIt := false
		for _, v := range env {
			if hasWordMatch(strings.ToLower(v), cmd) {
				singleVarHoldsIt = true
				break
			}
		}
		if !singleVarHoldsIt {
			return cmd, true
		}
	}
	return "", false
}

func analyzeVariableResolution(content string, env map[string]string) []Finding {
	var out []Finding
	foundExec, foundCmd := false, false
	for i, line := range splitLines(content) {
		if !strings.Contains(line, "$") {
			continue
		}
		resolved := resolveVariables(line, env)
		if resolved == line {
			continue
		}
		if !foundExec {
			if dl, exec, ok := containsDangerousPipe(resolved); ok {
				origLower := strings.ToLower(line)
				if !(strings.Contains(origLower, dl) && strings.Contains(origLower, exec)) {
					out = append(out, Finding{
						ID: "SA-VAR-CONCAT-EXEC", Points: 85,
						Description: fmt.Sprintf("variable concatenation resolves to '%s|%s' (line %d)", dl, exec, i+1),
						MatchedLine: trimSpace(line),
					})
					foundExec = true
					continue
				}
			}
		}
		if !foundCmd {
			if cmd, ok := containsMultiVarDangerousCmd(line, resolved, env); ok {
				out = append(out, Finding{
					ID: "SA-VAR-CONCAT-CMD", Points: 55,
					Description: fmt.Sprintf("variable concatenation resolves to '%s' (line %d)", cmd, i+1),
					MatchedLine: trimSpace(line),
				})
				foundCmd = true
			}
		}
		if foundExec && foundCmd {
			break
		}
	}
	return out
}

func analyzeIndirectExecution(content string, env map[string]string) []Finding {
	type dv struct{ name, cmd string }
	var dangerousVars []dv
	for name, value := range env {
		lower := strings.ToLower(value)
		for _, cmd := range dangerousCommands {
			if lower == cmd {
				dangerousVars = append(dangerousVars, dv{name, cmd})
				break
			}
		}
	}
	if len(dangerousVars) == 0 {
		return nil
	}
	for _, d := range dangerousVars {
		pattern := fmt.Sprintf(`(?m)(?:^|\||\|\||&&|;)\s*\$\{?%s\}?`, regexp.QuoteMeta(d.name))
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(content) {
			matched := ""
			for _, line := range splitLines(content) {
				if re.MatchString(line) {
					matched = trimSpace(line)
					break
				}
			}
			return []Finding{{
				ID: "SA-INDIRECT-EXEC", Points: 70,
				Description: fmt.Sprintf("variable $%s holds '%s' and is used in execution position", d.name, d.cmd),
				MatchedLine: matched,
			}}
		}
	}
	return nil
}

func analyzeCharByCharConstruction(content string) []Finding {
	for i, line := range splitLines(content) {
		total := len(printfSubshellRE.FindAllStringIndex(line, -1)) + len(echoSubshellRE.FindAllStringIndex(line, -1))
		if total >= 3 {
			return []Finding{{
				ID: "SA-CHARBYCHAR-CONSTRUCT", Points: 75,
				Description: fmt.Sprintf("%d printf/echo subshells on line %d (char-by-char command construction)", total, i+1),
				MatchedLine: trimSpace(line),
			}}
		}
	}
	return nil
}

func analyzeDataBlobs(content string) []Finding {
	var out []Finding
	inChecksumBlock := false
	hasHex, hasB64 := false, false
	for _, line := range splitLines(content) {
		if checksumArrayOpen.MatchString(line) {
			inChecksumBlock = true
		}
		skip := inChecksumBlock || checksumLineRE.MatchString(line)
		if inChecksumBlock && strings.Contains(line, ")") {
			inChecksumBlock = false
		}
		if skip {
			continue
		}
		if !hasHex && longHexRE.MatchString(line) {
			out = append(out, Finding{
				ID: "SA-DATA-BLOB-HEX", Points: 50,
				Description: "embedded long hex string (possible encoded payload)",
				MatchedLine: trimSpace(line),
			})
			hasHex = true
		}
		if !hasB64 && longBase64RE.MatchString(line) && !longHexRE.MatchString(line) {
			out = append(out, Finding{
				ID: "SA-DATA-BLOB-BASE64", Points: 50,
				Description: "embedded long base64 string (possible encoded payload)",
				MatchedLine: trimSpace(line),
			})
			hasB64 = true
		}
	}
	out = append(out, analyzeHeredocEntropy(content)...)
	return out
}

func analyzeHeredocEntropy(content string) []Finding {
	lines := splitLines(content)
	i := 0
	for i < len(lines) {
		if caps := heredocStartRE.FindStringSubmatch(lines[i]); caps != nil {
			delimiter := caps[1]
			var body strings.Builder
			i++
			for i < len(lines) {
				if strings.TrimSpace(lines[i]) == delimiter {
					break
				}
				body.WriteString(lines[i])
				body.WriteByte('\n')
				i++
			}
			b := body.String()
			if len(b) > 200 {
				entropy := shannonEntropy(b)
				if entropy > 5.0 {
					// A high-entropy heredoc is a ClassTrigger, not standalone
					// evidence: it fires on legitimate embedded base64/cert/font
					// blobs. It mints only when combined with a supply-chain
					// trigger (see IsMaliciousCombined).
					return []Finding{{
						ID: EntropyTriggerID, Points: 55, Class: ClassTrigger,
						Description: fmt.Sprintf("heredoc with high entropy (%.1f bits/byte, %d bytes)", entropy, len(b)),
					}}
				}
			}
		}
		i++
	}
	return nil
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	length := float64(len(s))
	var sum float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / length
		sum += -p * math.Log2(p)
	}
	return sum
}

func analyzeBinaryDownload(content string) []Finding {
	if !downloadToFileRE.MatchString(content) || !chmodExecRE.MatchString(content) {
		return nil
	}
	lower := strings.ToLower(content)
	for _, cmd := range buildCommands {
		if strings.Contains(lower, cmd) {
			return nil
		}
	}
	matched := ""
	for _, line := range splitLines(content) {
		if downloadToFileRE.MatchString(line) {
			matched = trimSpace(line)
			break
		}
	}
	return []Finding{{
		ID: "SA-BINARY-DOWNLOAD-NOCOMPILE", Points: 60,
		Description: "downloads file and chmod +x with no compilation step",
		MatchedLine: matched,
	}}
}
