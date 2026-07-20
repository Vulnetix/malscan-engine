package curation

import "testing"

func TestSet(t *testing.T) {
	s := NewBuilder().
		ClearPackage("npm", "left-pad", "1.3.0").
		ClearPackage("pypi", "requests", ""). // all versions
		FalsePositiveIOC("domain", "Example.com").
		DowngradeActor("actor-1").
		AllowActor("actor-3").
		Build()

	if !s.PackageCleared("npm", "left-pad", "1.3.0") {
		t.Error("exact package@version should be cleared")
	}
	if s.PackageCleared("npm", "left-pad", "1.4.0") {
		t.Error("other version must not be cleared")
	}
	if !s.PackageCleared("pypi", "requests", "9.9.9") {
		t.Error("version-less clear should cover any version")
	}
	if !s.IOCFalsePositive("DOMAIN", "example.com") {
		t.Error("IOC match should be case-insensitive")
	}
	if !s.ActorDowngraded("actor-1") || !s.ActorDowngraded("actor-3") {
		t.Error("downgraded + allowed actors are both downgraded")
	}
	if s.ActorAllowed("actor-1") {
		t.Error("actor-1 is only downgraded, not allowed")
	}
	if !s.ActorAllowed("actor-3") {
		t.Error("actor-3 should be allowed")
	}
	if s.Empty() {
		t.Error("set is not empty")
	}
	if !FromWire(Wire{}).Empty() {
		t.Error("zero wire is empty")
	}
}
