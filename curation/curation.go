// Package curation is the shared source of truth for customer false-positive
// feedback that both the Vulnetix CLI and the vdb-manager registry processors
// consult before flagging a subject as malware. It mirrors the role of the
// `allow` package (benign-indicator suppression) but is data-driven and supplied
// at runtime rather than compiled in: the backend aggregates per-customer FP
// decisions into a global consensus and delivers it to each consumer (the CLI
// via cli.malware-curation-get, vdb-manager via a DB load).
//
// Literal-threshold semantics (encoded by the backend consensus, honored here):
//   - a package@version marked FP by >=1 org  -> PackageCleared  (not malware)
//   - a threat actor marked FP by >=1 org      -> ActorDowngraded (no standalone attribution)
//   - a threat actor marked FP by >=3 orgs     -> ActorAllowed    (excluded entirely)
//   - an IOC (type,value) marked FP            -> IOCFalsePositive (never an indicator)
package curation

import (
	"encoding/json"
	"os"
	"strings"
)

// Set is an immutable snapshot of the current curation consensus. The zero value
// is a valid empty set (nothing cleared). Build it from JSON (LoadFile) or
// programmatically (NewBuilder).
type Set struct {
	clearedPackages  map[string]bool // key: eco\x00name\x00version  (version "" = all versions)
	fpIOCs           map[string]bool // key: type\x00value (lowercased)
	downgradedActors map[string]bool // actor id/key
	allowedActors    map[string]bool // actor id/key
}

// Wire is the JSON shape delivered by the backend and written to the overlay
// file. Every field is optional so older/newer peers interoperate.
type Wire struct {
	ClearedPackages   []PackageRef `json:"clearedPackages,omitempty"`
	FalsePositiveIOCs []IOCRef     `json:"falsePositiveIocs,omitempty"`
	DowngradedActors  []string     `json:"downgradedActors,omitempty"`
	AllowedActors     []string     `json:"allowedActors,omitempty"`
}

// PackageRef identifies a package@version. Version "" means all versions.
type PackageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

// IOCRef identifies an indicator by type + value.
type IOCRef struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func pkgKey(eco, name, ver string) string {
	return strings.ToLower(eco) + "\x00" + strings.ToLower(name) + "\x00" + strings.ToLower(ver)
}

func iocKey(typ, val string) string {
	return strings.ToLower(strings.TrimSpace(typ)) + "\x00" + strings.ToLower(strings.TrimSpace(val))
}

// FromWire builds a Set from the wire shape.
func FromWire(w Wire) *Set {
	s := &Set{
		clearedPackages:  map[string]bool{},
		fpIOCs:           map[string]bool{},
		downgradedActors: map[string]bool{},
		allowedActors:    map[string]bool{},
	}
	for _, p := range w.ClearedPackages {
		s.clearedPackages[pkgKey(p.Ecosystem, p.Name, p.Version)] = true
	}
	for _, i := range w.FalsePositiveIOCs {
		s.fpIOCs[iocKey(i.Type, i.Value)] = true
	}
	for _, a := range w.DowngradedActors {
		s.downgradedActors[strings.ToLower(strings.TrimSpace(a))] = true
	}
	for _, a := range w.AllowedActors {
		s.allowedActors[strings.ToLower(strings.TrimSpace(a))] = true
	}
	return s
}

// LoadFile reads a curation overlay JSON file. A missing file yields an empty
// Set with no error (the overlay is optional).
func LoadFile(path string) (*Set, error) {
	if strings.TrimSpace(path) == "" {
		return FromWire(Wire{}), nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return FromWire(Wire{}), nil
	}
	if err != nil {
		return nil, err
	}
	var w Wire
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	return FromWire(w), nil
}

// Empty reports whether the set carries no curation at all.
func (s *Set) Empty() bool {
	if s == nil {
		return true
	}
	return len(s.clearedPackages) == 0 && len(s.fpIOCs) == 0 &&
		len(s.downgradedActors) == 0 && len(s.allowedActors) == 0
}

// PackageCleared reports whether this package@version has been globally cleared
// as a false positive (any-single-customer FP by product decision). A version-less
// clear ("" version) covers every version.
func (s *Set) PackageCleared(eco, name, version string) bool {
	if s == nil {
		return false
	}
	if s.clearedPackages[pkgKey(eco, name, version)] {
		return true
	}
	return s.clearedPackages[pkgKey(eco, name, "")]
}

// IOCFalsePositive reports whether an indicator has been marked FP and must not
// become an indicator/finding.
func (s *Set) IOCFalsePositive(typ, value string) bool {
	if s == nil {
		return false
	}
	return s.fpIOCs[iocKey(typ, value)]
}

// ActorDowngraded reports whether a threat actor no longer counts as a standalone
// corroborator (>=1 FP). Allowed actors are also downgraded.
func (s *Set) ActorDowngraded(actor string) bool {
	if s == nil {
		return false
	}
	k := strings.ToLower(strings.TrimSpace(actor))
	return s.downgradedActors[k] || s.allowedActors[k]
}

// ActorAllowed reports whether a threat actor is fully allow-listed (>=3 FP) and
// must be excluded entirely (like a legit maintainer).
func (s *Set) ActorAllowed(actor string) bool {
	if s == nil {
		return false
	}
	return s.allowedActors[strings.ToLower(strings.TrimSpace(actor))]
}

// Builder accumulates curation entries programmatically (vdb-manager builds one
// from a DB load; tests build one inline).
type Builder struct{ w Wire }

// NewBuilder returns an empty Builder.
func NewBuilder() *Builder { return &Builder{} }

// ClearPackage marks a package@version cleared (version "" = all versions).
func (b *Builder) ClearPackage(eco, name, version string) *Builder {
	b.w.ClearedPackages = append(b.w.ClearedPackages, PackageRef{eco, name, version})
	return b
}

// FalsePositiveIOC marks an indicator FP.
func (b *Builder) FalsePositiveIOC(typ, value string) *Builder {
	b.w.FalsePositiveIOCs = append(b.w.FalsePositiveIOCs, IOCRef{typ, value})
	return b
}

// DowngradeActor marks an actor downgraded.
func (b *Builder) DowngradeActor(actor string) *Builder {
	b.w.DowngradedActors = append(b.w.DowngradedActors, actor)
	return b
}

// AllowActor marks an actor allow-listed.
func (b *Builder) AllowActor(actor string) *Builder {
	b.w.AllowedActors = append(b.w.AllowedActors, actor)
	return b
}

// Build finalizes the Set.
func (b *Builder) Build() *Set { return FromWire(b.w) }
