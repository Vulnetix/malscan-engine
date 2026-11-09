package curation

import (
	"os"
	"path/filepath"
	"testing"
)

// writeOverlay writes a curation overlay JSON body to a temp file and returns
// its path.
func writeOverlay(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "overlay.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadFileWireRoundTrip pins the JSON wire contract of LoadFile: the four
// Wire fields survive the overlay file -> Set mapping, with pkgKey/iocKey
// case-folding, iocKey whitespace trimming, actor normalization and the
// version-less clear covering every version. The wire is consumed out-of-process
// (cli.malware-curation-get, vdb-manager DB load), so a shape change must fail
// here.
func TestLoadFileWireRoundTrip(t *testing.T) {
	path := writeOverlay(t, `{
		"clearedPackages": [
			{"ecosystem": "NPM", "name": "left-pad", "version": "1.3.0"},
			{"ecosystem": "pypi", "name": "Requests", "version": ""}
		],
		"falsePositiveIocs": [
			{"type": "Domain", "value": "  Example.COM  "},
			{"type": "ipv4", "value": "203.0.113.9"}
		],
		"downgradedActors": ["Actor-One"],
		"allowedActors": [" actor-three "]
	}`)

	s, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("expected a Set")
	}
	// Exact package@version clear; keys are case-folded on the wire.
	if !s.PackageCleared("npm", "left-pad", "1.3.0") {
		t.Error("exact package@version should be cleared")
	}
	if s.PackageCleared("npm", "left-pad", "1.4.0") {
		t.Error("other version must not be cleared")
	}
	// A version-less clear ("") covers every version.
	if !s.PackageCleared("pypi", "requests", "9.9.9") {
		t.Error("version-less clear should cover any version")
	}
	// IOC keys are case-insensitive and trimmed on both sides.
	if !s.IOCFalsePositive("DOMAIN", "example.com") {
		t.Error("IOC match should be case-insensitive")
	}
	if !s.IOCFalsePositive("IPv4", " 203.0.113.9 ") {
		t.Error("IOC match should ignore surrounding whitespace")
	}
	// Actor keys are lowercased and trimmed; allowed actors are also downgraded.
	if !s.ActorDowngraded("actor-one") || !s.ActorDowngraded("ACTOR-THREE") {
		t.Error("downgraded + allowed actors are both downgraded")
	}
	if s.ActorAllowed("actor-one") {
		t.Error("actor-one is only downgraded, not allowed")
	}
	if !s.ActorAllowed("actor-three") {
		t.Error("actor-three should be allowed")
	}
	if s.Empty() {
		t.Error("set is not empty")
	}
}

func TestLoadFileMissingFile(t *testing.T) {
	s, err := LoadFile(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("missing overlay is optional: %v", err)
	}
	if s == nil {
		t.Fatal("expected an empty Set")
	}
	if !s.Empty() {
		t.Error("missing file should yield an empty Set")
	}
}

func TestLoadFileEmptyPath(t *testing.T) {
	s, err := LoadFile("")
	if err != nil {
		t.Fatalf("empty path is optional: %v", err)
	}
	if s == nil {
		t.Fatal("expected an empty Set")
	}
	if !s.Empty() {
		t.Error("empty path should yield an empty Set")
	}
}

func TestLoadFileMalformed(t *testing.T) {
	path := writeOverlay(t, "{not json")
	if _, err := LoadFile(path); err == nil {
		t.Fatal("malformed JSON should return an error")
	}
}
