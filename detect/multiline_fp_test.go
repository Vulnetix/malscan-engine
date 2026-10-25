package detect

import "testing"

// A match that crosses a line break is kept only for a rule written to span lines ([\s\S]);
// it reports the line the match starts on. Any other cross-line match is an accident.
func TestReportableLineMultiline(t *testing.T) {
	loadPatterns()
	var spanning, single compiledPattern
	for _, ps := range patternsBySection {
		for _, p := range ps {
			switch p.id {
			case "DART-HTTPCLIENT-PROCESS-EXEC":
				spanning = p
			case "P-CURL-PIPE":
				single = p
			}
		}
	}
	if !spanning.multiline || single.multiline {
		t.Fatalf("multiline flags: DART %v, P-CURL-PIPE %v", spanning.multiline, single.multiline)
	}
	src := "final c = HttpClient();\nfinal body = await fetch(c);\nawait Process.run('sh', ['-c', body]);\n"
	line, keep := reportableLine(spanning, src)
	if !keep || line != "final c = HttpClient();" {
		t.Errorf("spanning rule: %q %v", line, keep)
	}
	if _, keep := reportableLine(single, "no single line\nmatches here"); keep {
		t.Error("a non-matching rule cannot be kept")
	}
}

// The empty-line mints the audit withdrew: a rule word in one line of prose and a flag on a later
// line no longer join into a finding with nothing to show.
func TestCrossLineAccidentDropped(t *testing.T) {
	loadPatterns()
	src := "Decodes base32\nids and compares them.\nflags := []string{\"-d\"}\n"
	for _, ps := range patternsBySection {
		for _, p := range ps {
			if p.multiline || !p.re.MatchString(src) {
				continue
			}
			if line, keep := reportableLine(p, src); keep && line == "" {
				t.Errorf("%s kept a cross-line match with no line", p.id)
			}
		}
	}
}
