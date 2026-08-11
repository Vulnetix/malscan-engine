package detect

import (
	_ "embed"
	"fmt"
	"github.com/vulnetix/malscan-engine/allow"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

//go:embed data/patterns.toml
var patternsTOML []byte

// patternRule is one rule as declared in patterns.toml.
type patternRule struct {
	ID           string `toml:"id"`
	Pattern      string `toml:"pattern"`
	Points       int    `toml:"points"`
	Description  string `toml:"description"`
	OverrideGate bool   `toml:"override_gate"`
	// HookOnly marks a dual-use command (bare aria2c/docker/npx-remote, …) that is
	// malicious evidence ONLY when it appears in an auto-execution surface (an
	// install hook, or a PkgbuildContent whose processor set PkgbuildExecutes).
	// Outside such a surface the hit is demoted to ClassContext corroboration. Never
	// set on override_gate rules (reverse/bind shells, curl|sh) — those are proof
	// regardless of context.
	HookOnly bool `toml:"hook_only"`
	// PkgbuildOnly marks a rule that is only meaningful for Arch-PKGBUILD source
	// hygiene (plain-HTTP source, raw-IP source URL). It is skipped entirely when
	// the matched content is neither a PKGBUILD nor an auto-execution surface, so
	// it stops firing on npm/pypi/etc. declarative manifests (the P-HTTP-SOURCE /
	// P-RAW-IP-URL false positives).
	PkgbuildOnly bool `toml:"pkgbuild_only"`
	// Ecosystems scopes a rule to the ecosystems it was written for. Empty (the
	// default, and the case for almost every rule) means it runs everywhere.
	// Set it whenever a pattern encodes one language's idioms — a Rust build.rs
	// call, an npm lifecycle hook — because callers such as the package firewall
	// run every detector against every ecosystem's metadata.
	Ecosystems []string `toml:"ecosystems"`
}

// compiledPattern is a runtime-ready rule.
type compiledPattern struct {
	id           string
	re           *regexp.Regexp
	points       int
	description  string
	overrideGate bool
	hookOnly     bool
	pkgbuildOnly bool
	ecosystems   map[string]bool // empty = every ecosystem
}

// appliesTo reports whether the rule should run for this ecosystem. A rule with
// no ecosystems listed runs everywhere, which keeps every existing rule
// behaving exactly as before.
//
// Without this, a rule written for one language judged every other: the Rust
// build.rs rule P-CARGO-BUILD-DOWNLOAD reported chalk, eslint, moment and eleven
// more npm packages as "build.rs downloads a remote resource at build time",
// because the package firewall feeds a registry packument through the same
// detectors and nothing said which language a rule was about.
func (p compiledPattern) appliesTo(eco string) bool {
	if len(p.ecosystems) == 0 {
		return true
	}
	if eco == "" {
		// Caller did not say. Run the rule rather than silently skip detection.
		return true
	}
	return p.ecosystems[strings.ToLower(strings.TrimSpace(eco))]
}

var (
	patternsOnce      sync.Once
	patternsBySection map[string][]compiledPattern
	skippedPatterns   []string // ids that failed to compile under RE2
)

// loadPatterns parses and compiles patterns.toml once. RE2-incompatible rules
// (lookaround/backreferences — none at time of writing) are logged and skipped
// rather than crashing the processor.
func loadPatterns() {
	patternsOnce.Do(func() {
		var raw map[string][]patternRule
		if err := toml.Unmarshal(patternsTOML, &raw); err != nil {
			panic(fmt.Sprintf("malscan-engine/detect: parse patterns.toml: %v", err))
		}
		patternsBySection = make(map[string][]compiledPattern, len(raw))
		for section, rules := range raw {
			for _, r := range rules {
				re, err := regexp.Compile(r.Pattern)
				if err != nil {
					skippedPatterns = append(skippedPatterns, r.ID)
					continue
				}
				var ecos map[string]bool
				if len(r.Ecosystems) > 0 {
					ecos = make(map[string]bool, len(r.Ecosystems))
					for _, e := range r.Ecosystems {
						ecos[strings.ToLower(strings.TrimSpace(e))] = true
					}
				}
				patternsBySection[section] = append(patternsBySection[section], compiledPattern{
					id: r.ID, re: re, points: r.Points,
					description: r.Description, overrideGate: r.OverrideGate,
					hookOnly: r.HookOnly, pkgbuildOnly: r.PkgbuildOnly,
					ecosystems: ecos,
				})
			}
		}
		sort.Strings(skippedPatterns)
	})
}

// SkippedPatterns returns the ids of any patterns.toml rules that failed RE2
// compilation. Useful for the build-time test and startup logging.
func SkippedPatterns() []string {
	loadPatterns()
	return append([]string(nil), skippedPatterns...)
}

// LogStartup emits a one-line summary of the loaded ruleset.
func LogStartup(logger *slog.Logger) {
	loadPatterns()
	total := 0
	for _, ps := range patternsBySection {
		total += len(ps)
	}
	logger.Info("malscan detect engine loaded",
		"patternRules", total,
		"skippedRules", len(skippedPatterns),
		"skipped", skippedPatterns,
	)
}

// evidenceThreshold is the minimum points for a pattern hit to count as
// malicious *evidence* (sufficient to mint on its own). Lower-weight rules are
// dual-use / quality / risk signals — plain http source, rsync/scp/sftp
// downloads, `ruby -e`, `systemctl enable` — which are recorded as ClassContext
// and never mint alone. Override-gate rules (the strongest download-and-execute /
// reverse-shell indicators) are always evidence regardless of points.
const evidenceThreshold = 40

// matchSection matches one TOML section against content.
// matchSection matches one TOML section against content. inHookSurface reports
// whether content auto-executes at build/install time (an install hook, or a
// PkgbuildContent the caller flagged PkgbuildExecutes). hook_only patterns found
// outside such a surface are demoted to ClassContext corroboration.
func matchSection(content, section, category, idPrefix string, inHookSurface bool, eco string, findings []Finding) []Finding {
	loadPatterns()
	pkgbuildLike := inHookSurface || looksLikePkgbuild(content)
	for _, p := range patternsBySection[section] {
		// An ecosystem-scoped rule is meaningless elsewhere. Checked before the
		// regex so a scoped rule costs nothing on the ecosystems it does not
		// apply to.
		if !p.appliesTo(eco) {
			continue
		}
		if p.re.MatchString(content) {
			// PKGBUILD-source-hygiene rules carry no signal on a declarative
			// (non-PKGBUILD, non-hook) manifest — skip them entirely there.
			if p.pkgbuildOnly && !pkgbuildLike {
				continue
			}
			class := ClassEvidence
			if !p.overrideGate && p.points < evidenceThreshold {
				class = ClassContext
			}
			if p.hookOnly && !inHookSurface {
				// Dual-use command outside an auto-exec surface. A low-weight
				// (sub-evidence) signal there is pure corroboration noise — drop it;
				// a higher-weight one is still recorded as ClassContext.
				if p.points < evidenceThreshold {
					continue
				}
				class = ClassContext
			}
			line, keep := reportableLine(p.id, content, p.re)
			if !keep {
				continue
			}
			findings = append(findings, Finding{
				ID:          idPrefix + p.id,
				Category:    category,
				Class:       class,
				CWE:         cweForSignal(p.id),
				Points:      p.points,
				Description: p.description,
				MatchedLine: line,
			})
		}
	}
	return findings
}

// firstMatchingLine returns the trimmed first line of content matching re.
func firstMatchingLine(content string, re *regexp.Regexp) string {
	for _, line := range splitLines(content) {
		if re.MatchString(line) {
			return trimSpace(line)
		}
	}
	return ""
}

// reportableLine picks the line to report for a match, applying the per-rule
// suppressors, and reports whether the finding survives at all.
//
// It walks EVERY matching line rather than judging only the first. Suppressing on
// the first match alone loses true positives: a file whose first `exec($x)` is a
// method declaration and whose tenth is a real command sink would be dropped
// wholesale. A finding is suppressed only when no matching line survives, so
// suppression can remove false positives but cannot hide a genuine hit sitting
// further down the same file.
//
// When the pattern matches the content as a whole but no individual line does (a
// match spanning a line break), the finding is kept with an empty line — the same
// conservative direction the per-rule suppressors take on an unparseable line.
func reportableLine(id, content string, re *regexp.Regexp) (string, bool) {
	matched := false
	for _, raw := range splitLines(content) {
		if !re.MatchString(raw) {
			continue
		}
		matched = true
		line := trimSpace(raw)
		if !suppressLine(id, line) {
			return line, true
		}
	}
	if !matched {
		return "", true
	}
	return "", false
}

// suppressLine reports whether this rule considers this specific line a false
// positive. Rules with no suppressor still get the comment guard.
func suppressLine(id, line string) bool {
	if IsCommentLine(line) {
		return true
	}
	switch id {
	case "P-RAW-IP-URL":
		return suppressNonRoutableIPURL(id, line)
	case "PHP-SHELL-EXEC-VAR":
		return phpFunctionDeclRe.MatchString(line)
	case "PHP-ASSERT-VAR":
		return phpAssertBooleanRe.MatchString(line)
	}
	return false
}

// phpAssertBooleanRe matches an assert() whose argument is plainly a boolean
// expression rather than a string of code.
//
// PHP-ASSERT-VAR exists for the historical eval sink: assert('$code') evaluated a
// STRING as PHP. Passing an expression never did that, and string assert was removed
// outright in PHP 8. Meanwhile `assert($x instanceof Foo)` is the standard way
// psalm/phpstan-annotated code states an invariant, and it compiles to nothing when
// zend.assertions is off.
//
// Measured on production 2026-08-08: PHP-ASSERT-VAR was the SOLE evidence for 665 of
// packagist's malware mints, and a replay of the lines it matched showed 126 of 150
// still firing after the earlier boundary fix — because that fix only addressed
// $obj->assert() and Foo::assert(), not the argument. The sampled lines were
// `assert($response->getStatusCode() === 204);` and `assert($iterator instanceof
// \Iterator);`.
//
// A bare `assert($code)` with no operator still fires: that is the shape that could
// carry a code string.
var phpAssertBooleanRe = regexp.MustCompile(
	`assert\s*\(\s*\$[^)]*?(instanceof|===|!==|==|!=|>=|<=|&&|\|\||->|::|\bis_[a-z_]+\s*\(|\bcount\s*\(|\bin_array\s*\()`)

// IsCommentLine reports whether a line is a comment — text the interpreter never
// executes.
//
// A comment cannot be a behaviour. Measured on production 2026-08-08 by replaying the
// lines packagist and pypi mints actually matched through the engine, the recurring
// live false positive was a rule firing on documentation ABOUT the behaviour it
// detects, in packages that do the opposite of malware:
//
//	P-TELEGRAM-BOT  "* You should set [telegram bot token](https://core.telegram.org/…"
//	P-CRON-CREATE   "* CronManager provides easy access to the crontable"
//	P-URL-SHORTENER "* @link http://bit.ly/hg3gHb"
//	P-CRYPTO-WALLET "#   \"contractAddress\": \"0xee2a03aa6dacf51c18679c516ad5283d8e7c2637\","
//	P-CRON-CREATE   "# 2026 March equinox is ~14:46 UTC Mar 20; at 12:08 UTC (solar noon"
//
// Because reportableLine only suppresses when EVERY matching line is suppressed, a
// payload that also appears on one executable line is still reported — this drops
// findings whose entire basis is prose, not findings that happen to be discussed in a
// comment somewhere in the file.
//
// Deliberately excluded: `;` (a shell statement separator as often as an ini comment)
// and a bare `--` flag. `*` counts only in the PHPDoc/JSDoc continuation form (`* `
// followed by something other than `)`), so a shell case label like `*) curl x | sh ;;`
// is NOT read as a comment.
func IsCommentLine(line string) bool {
	s := trimSpace(line)
	if s == "" {
		return false
	}
	switch {
	case strings.HasPrefix(s, "#"):
		return true
	case strings.HasPrefix(s, "//"):
		return true
	case strings.HasPrefix(s, "/*"):
		return true
	case strings.HasPrefix(s, "*/"):
		// A block-comment close stands alone; `*/*.php` is a glob.
		return trimSpace(s[2:]) == ""
	case strings.HasPrefix(s, "<!--"):
		return true
	case strings.HasPrefix(s, "-- "):
		return true
	case strings.HasPrefix(s, "* "):
		// PHPDoc/JSDoc continuation, but not `* )` — a shell case label.
		return !strings.HasPrefix(trimSpace(s[2:]), ")")
	}
	return false
}

// phpFunctionDeclRe matches a PHP function DECLARATION of a command-sink name, which
// is not a call to one.
//
// PHP-SHELL-EXEC-VAR's boundary guard was added for call sites — curl_exec($ch),
// $pdo->exec($sql), Foo::exec($x) — and a declaration slips straight through it,
// because `public function exec($query)` puts an ordinary space before `exec`.
// Measured on production 2026-08-08: the rule was the SOLE evidence for 6,418 of
// packagist's 15,678 malware mints (41%), the single largest false-positive driver in
// the corpus, and its sampled lines were `public function exec($query)` and
// `public function exec($statement)` — database and process abstractions declaring
// their own exec method, which every DBAL, queue and console library has.
//
// A declaration cannot be the sink: defining `exec($cmd)` does not run anything. The
// body that calls the real system function is matched on its own line.
var phpFunctionDeclRe = regexp.MustCompile(
	`\bfunction\s+&?\s*(system|exec|shell_exec|passthru|proc_open|popen)\s*\(`)

// rawIPURLRe extracts the address from a P-RAW-IP-URL match so it can be judged.
var rawIPURLRe = regexp.MustCompile(`https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// suppressNonRoutableIPURL drops a P-RAW-IP-URL hit whose address is not routable.
//
// The rule's point is "this package talks to a bare address instead of a hostname",
// which is only indicative when the address could actually be a C2. http://127.0.0.1
// is a dev server, http://0.0.0.0 is a bind address, 192.168.x.x is a LAN, and the
// RFC-5737 blocks are documentation — all of them appear in ordinary source.
// Measured on production 2026-08-07, P-RAW-IP-URL was the SOLE evidence for 742
// malware mints across packagist, pypi, go and cargo.
//
// This lives in Go rather than in the pattern because allow.IP already encodes every
// reserved range correctly; a hand-written regex for "routable" got 11-19 and
// 200-255 wrong on the first attempt while still admitting 127.
func suppressNonRoutableIPURL(id, line string) bool {
	if id != "P-RAW-IP-URL" || line == "" {
		return false
	}
	m := rawIPURLRe.FindStringSubmatch(line)
	if m == nil {
		// The rule matched somewhere in the content but not in the line we chose to
		// report; keep the finding rather than dropping it on a formatting detail.
		return false
	}
	return allow.IP(m[1])
}
