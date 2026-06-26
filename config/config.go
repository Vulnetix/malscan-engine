// Package config supplies the per-ecosystem malscan capability configuration, so
// the engine can short-circuit detectors a human has turned off for a given
// registry — at runtime, without a rebuild.
//
// Two layers, lowest precedence first:
//
//  1. Committed repo DEFAULTS — config/defaults/<slug>.json, authored in the
//     Rust frontend and embedded into the binary here (//go:embed). Always
//     present, so the engine has a sane baseline wherever it runs. See Defaults.
//  2. System OVERRIDES — <Dir()>/<slug>.json on the host, edited by an operator.
//     Overlaid on the defaults per key (and the endpoint, if non-empty). See Dir
//     and LoadEcosystem.
//
// Resolve merges the two. Each document is:
//
//	{
//	  "ecosystem": "npm",
//	  "registry_endpoint": "https://registry.npmjs.org",
//	  "capabilities": { "manifest-patterns": true, "checksum": false, ... }
//	}
//
// Dir() resolves the override directory: MALSCAN_CONFIG_DIR if set, else
// <user-config-dir>/malscan-engine (os.UserConfigDir — $XDG_CONFIG_HOME or
// $HOME/.config on Linux). The frontend does NOT write here; it manages the repo
// defaults only.
//
// Capability keys are the contract shared with the frontend
// (frontend/src/model.rs) and the engine (the detect.Cap* constants). Wire a
// resolved config into detection by assigning EcosystemConfig.Capabilities to
// detect.PackageContext.Capabilities before calling detect.Detect; consult
// EcosystemConfig.Enabled for the detectors invoked outside Detect
// (ownership/badhash/ioc/goodkeys).
package config

import (
	"embed"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed defaults/*.json
var defaultsFS embed.FS

var (
	defaultsOnce sync.Once
	defaultsMap  map[string]EcosystemConfig
	defaultsErr  error
)

// EcosystemConfig is one ecosystem's persisted settings.
type EcosystemConfig struct {
	Ecosystem        string          `json:"ecosystem"`
	RegistryEndpoint string          `json:"registry_endpoint"`
	Capabilities     map[string]bool `json:"capabilities"`
}

// Dir resolves the configuration directory (see the package doc).
func Dir() string {
	if d := os.Getenv("MALSCAN_CONFIG_DIR"); d != "" {
		return d
	}
	if base, err := os.UserConfigDir(); err == nil {
		return filepath.Join(base, "malscan-engine")
	}
	return "malscan-engine-config"
}

// Path returns the on-disk path of an ecosystem's config within dir.
func Path(dir, slug string) string {
	return filepath.Join(dir, slug+".json")
}

// LoadEcosystem reads one ecosystem's config from dir. It returns (nil, nil)
// when the file does not exist — callers should treat a nil config as
// "everything enabled" (see EcosystemConfig.Enabled). The read is cheap, so a
// per-scan call picks up frontend edits live.
func LoadEcosystem(dir, slug string) (*EcosystemConfig, error) {
	b, err := os.ReadFile(Path(dir, slug))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var c EcosystemConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Ecosystem == "" {
		c.Ecosystem = slug
	}
	return &c, nil
}

// Load reads every "*.json" config in dir, keyed by ecosystem slug. A missing
// directory yields an empty map and no error.
func Load(dir string) (map[string]EcosystemConfig, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]EcosystemConfig{}, nil
		}
		return nil, err
	}
	out := make(map[string]EcosystemConfig)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		slug := strings.TrimSuffix(e.Name(), ".json")
		c, err := LoadEcosystem(dir, slug)
		if err != nil {
			return nil, err
		}
		if c != nil {
			out[c.Ecosystem] = *c
		}
	}
	return out, nil
}

// Enabled reports whether a capability is active. A nil config (no file on
// disk), a nil capability map, or an absent key all mean enabled — so a config
// need only record the capabilities a human disabled, and a newly added
// detector still runs against an older config.
func (c *EcosystemConfig) Enabled(capKey string) bool {
	if c == nil || c.Capabilities == nil {
		return true
	}
	if v, ok := c.Capabilities[capKey]; ok {
		return v
	}
	return true
}

// Defaults returns the committed repo defaults embedded into the binary, keyed
// by ecosystem slug. Parsed once and cached.
func Defaults() (map[string]EcosystemConfig, error) {
	defaultsOnce.Do(func() {
		defaultsMap = make(map[string]EcosystemConfig)
		entries, err := defaultsFS.ReadDir("defaults")
		if err != nil {
			defaultsErr = err
			return
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			b, err := defaultsFS.ReadFile("defaults/" + e.Name())
			if err != nil {
				defaultsErr = err
				return
			}
			var c EcosystemConfig
			if err := json.Unmarshal(b, &c); err != nil {
				defaultsErr = err
				return
			}
			if c.Ecosystem == "" {
				c.Ecosystem = strings.TrimSuffix(e.Name(), ".json")
			}
			defaultsMap[c.Ecosystem] = c
		}
	})
	return defaultsMap, defaultsErr
}

// Resolve returns the effective config for slug: the committed embedded default
// overlaid with the system override file in dir (if any). The override overlays
// per key (and the endpoint, if non-empty), so a partial override only changes
// what it lists. The result is always non-nil; its Capabilities map is nil when
// neither layer exists (Enabled then reports everything on).
func Resolve(dir, slug string) (*EcosystemConfig, error) {
	merged := &EcosystemConfig{Ecosystem: slug}

	defs, err := Defaults()
	if err != nil {
		return nil, err
	}
	if d, ok := defs[slug]; ok {
		merged.RegistryEndpoint = d.RegistryEndpoint
		merged.Capabilities = maps.Clone(d.Capabilities)
	}

	ov, err := LoadEcosystem(dir, slug)
	if err != nil {
		return nil, err
	}
	if ov != nil {
		if ov.RegistryEndpoint != "" {
			merged.RegistryEndpoint = ov.RegistryEndpoint
		}
		if len(ov.Capabilities) > 0 && merged.Capabilities == nil {
			merged.Capabilities = make(map[string]bool, len(ov.Capabilities))
		}
		maps.Copy(merged.Capabilities, ov.Capabilities)
	}
	return merged, nil
}

// ResolveDefault resolves slug using the system override Dir(). This is the
// usual entry point for a processor.
func ResolveDefault(slug string) (*EcosystemConfig, error) {
	return Resolve(Dir(), slug)
}
