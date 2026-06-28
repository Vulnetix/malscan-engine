package badnet

import (
	"path/filepath"
	"testing"
)

func TestWriteAndLoadDirRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewEmpty()
	s.AddIP("45.137.21.9")
	s.AddIP("2606:4700::1111")
	s.AddDomain("malware-drop.xyz")
	s.AddEmail("scammer@evil-c2.ru")

	changed, err := s.WriteFiles(dir)
	if err != nil {
		t.Fatalf("WriteFiles: %v", err)
	}
	if changed == 0 {
		t.Fatal("expected files to be written")
	}
	// Re-writing identical content is a no-op.
	if again, err := s.WriteFiles(dir); err != nil || again != 0 {
		t.Errorf("re-write should be a no-op, got changed=%d err=%v", again, err)
	}

	loaded, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if !loaded.HasIP("45.137.21.9") || !loaded.HasIP("2606:4700:0000:0000:0000:0000:0000:1111") {
		t.Error("loaded set missing IPs")
	}
	if !loaded.HasDomain("malware-drop.xyz") {
		t.Error("loaded set missing domain")
	}
	if !loaded.HasEmail("scammer@evil-c2.ru") {
		t.Error("loaded set missing email")
	}
}

func TestLoadDirMissingIsEmptyNotError(t *testing.T) {
	s, err := LoadDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing dir should not error: %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("expected empty set, got %d", s.Len())
	}
}

func TestMerge(t *testing.T) {
	base := NewEmpty()
	base.AddIP("45.137.21.9")
	overlay := NewEmpty()
	overlay.AddIP("185.225.74.12")
	overlay.AddDomain("malware-drop.xyz")

	base.Merge(overlay)
	if !base.HasIP("45.137.21.9") || !base.HasIP("185.225.74.12") || !base.HasDomain("malware-drop.xyz") {
		t.Errorf("merge incomplete: %+v", base.IPs())
	}
}
