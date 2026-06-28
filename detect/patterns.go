package detect

import (
	_ "embed"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
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
				patternsBySection[section] = append(patternsBySection[section], compiledPattern{
					id: r.ID, re: re, points: r.Points,
					description: r.Description, overrideGate: r.OverrideGate,
					hookOnly: r.HookOnly, pkgbuildOnly: r.PkgbuildOnly,
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
func matchSection(content, section, category, idPrefix string, inHookSurface bool, findings []Finding) []Finding {
	loadPatterns()
	pkgbuildLike := inHookSurface || looksLikePkgbuild(content)
	for _, p := range patternsBySection[section] {
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
			findings = append(findings, Finding{
				ID:          idPrefix + p.id,
				Category:    category,
				Class:       class,
				CWE:         cweForSignal(p.id),
				Points:      p.points,
				Description: p.description,
				MatchedLine: firstMatchingLine(content, p.re),
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
