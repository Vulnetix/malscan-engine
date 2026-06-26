package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, dir, slug, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(dir, slug), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadEcosystemAndEnabled(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "npm", `{
		"ecosystem": "npm",
		"registry_endpoint": "https://registry.npmjs.org",
		"capabilities": { "manifest-patterns": true, "checksum": false }
	}`)

	c, err := LoadEcosystem(dir, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("expected a config")
	}
	if c.RegistryEndpoint != "https://registry.npmjs.org" {
		t.Fatalf("endpoint = %q", c.RegistryEndpoint)
	}
	if !c.Enabled("manifest-patterns") {
		t.Error("manifest-patterns should be enabled")
	}
	if c.Enabled("checksum") {
		t.Error("checksum should be disabled")
	}
	// Absent key defaults to enabled.
	if !c.Enabled("onion-c2") {
		t.Error("absent key should default to enabled")
	}
}

func TestLoadEcosystemMissingIsNil(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadEcosystem(dir, "pypi")
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Fatal("missing file should return nil config")
	}
	// A nil config enables everything.
	if !c.Enabled("anything") {
		t.Error("nil config should report enabled")
	}
}

func TestLoadAll(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "npm", `{"ecosystem":"npm","capabilities":{"checksum":false}}`)
	writeConfig(t, dir, "aur", `{"ecosystem":"aur","capabilities":{}}`)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ignore me"), 0o644); err != nil {
		t.Fatal(err)
	}

	all, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(all))
	}
	npm := all["npm"]
	if npm.Enabled("checksum") {
		t.Error("npm checksum should be disabled")
	}
}

func TestLoadMissingDirIsEmpty(t *testing.T) {
	all, err := Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Fatalf("expected empty map, got %d", len(all))
	}
}

func TestDirEnvOverride(t *testing.T) {
	t.Setenv("MALSCAN_CONFIG_DIR", "/tmp/custom-malscan")
	if got := Dir(); got != "/tmp/custom-malscan" {
		t.Fatalf("Dir() = %q, want /tmp/custom-malscan", got)
	}
}

func TestDefaultsEmbedded(t *testing.T) {
	defs, err := Defaults()
	if err != nil {
		t.Fatal(err)
	}
	// All eight ecosystems are committed.
	for _, slug := range []string{"aur", "homebrew", "npm", "pypi", "rubygems", "go", "cargo", "nuget"} {
		d, ok := defs[slug]
		if !ok {
			t.Fatalf("missing embedded default for %q", slug)
		}
		if !d.Enabled("manifest-patterns") {
			t.Errorf("%s: manifest-patterns should default enabled", slug)
		}
	}
	// install-script is an AUR capability but not a Go-modules one.
	if _, ok := defs["go"].Capabilities["install-script"]; ok {
		t.Error("go default should not list install-script")
	}
	if _, ok := defs["npm"].Capabilities["install-script"]; !ok {
		t.Error("npm default should list install-script")
	}
}

func TestResolveOverlaysDefaults(t *testing.T) {
	// No override file: Resolve returns the embedded default.
	dir := t.TempDir()
	npm, err := Resolve(dir, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if !npm.Enabled("checksum-stub-never") { // absent key → enabled
		t.Error("absent key should be enabled")
	}
	if !npm.Enabled("manifest-patterns") {
		t.Error("default manifest-patterns should be enabled")
	}
	if npm.RegistryEndpoint != "https://registry.npmjs.org" {
		t.Errorf("default endpoint not applied: %q", npm.RegistryEndpoint)
	}

	// A partial override disables one capability and changes the endpoint;
	// everything else falls back to the embedded default.
	writeConfig(t, dir, "npm", `{
		"ecosystem":"npm",
		"registry_endpoint":"https://npm.internal/mirror",
		"capabilities":{"onion-c2":false}
	}`)
	npm, err = Resolve(dir, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if npm.Enabled("onion-c2") {
		t.Error("override should disable onion-c2")
	}
	if !npm.Enabled("manifest-patterns") {
		t.Error("non-overridden default should stay enabled")
	}
	if npm.RegistryEndpoint != "https://npm.internal/mirror" {
		t.Errorf("override endpoint not applied: %q", npm.RegistryEndpoint)
	}
}
