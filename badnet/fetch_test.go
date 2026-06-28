package badnet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestCuratedFeedsIncludeHighConfidenceCandidates(t *testing.T) {
	urls := strings.Join(FeedURLs(), "\n")
	for _, want := range []string{
		"https://feeds.crowdsec.net/free/2be9a716-39b8-5c18-bc9e-4ba7aefd8831.json",
		"https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
		"https://urlhaus.abuse.ch/downloads/hostfile/",
	} {
		if !strings.Contains(urls, want) {
			t.Fatalf("curated feed list missing %s", want)
		}
	}
}

func TestFetchWithFeedsFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hosts.txt":
			_, _ = w.Write([]byte("127.0.0.1 custom.badactor.ru\n127.0.0.1 github.com\n"))
		case "/ips.txt":
			_, _ = w.Write([]byte("45.137.21.9\n1.2.3.0/24\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	feedsPath := filepath.Join(t.TempDir(), "feeds.json")
	body := `{
		"schema_version": "badnet-feeds/v1",
		"feeds": [
			{"key": "custom-hosts", "url": "` + srv.URL + `/hosts.txt", "parser": "hosts", "enabled": true},
			{"key": "custom-ips", "url": "` + srv.URL + `/ips.txt", "parser": "iplist", "enabled": true},
			{"key": "disabled", "url": "` + srv.URL + `/disabled.txt", "parser": "iplist", "enabled": false}
		]
	}`
	if err := os.WriteFile(feedsPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write feeds file: %v", err)
	}

	set, results, err := FetchWithFeedsFile(context.Background(), srv.Client(), feedsPath)
	if err != nil {
		t.Fatalf("FetchWithFeedsFile: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected two enabled feed results, got %d: %+v", len(results), results)
	}
	if !set.HasIP("45.137.21.9") {
		t.Error("custom ip feed did not populate set")
	}
	if !set.HasDomain("custom.badactor.ru") {
		t.Error("custom hosts feed did not populate set")
	}
	if set.HasDomain("github.com") || set.HasIP("1.2.3.0") {
		t.Error("allow/CIDR filtering should still apply to custom feeds")
	}

	outDir := t.TempDir()
	if _, err := set.WriteFiles(outDir); err != nil {
		t.Fatalf("WriteFiles: %v", err)
	}
	header, err := os.ReadFile(filepath.Join(outDir, "bad-ipv4.txt"))
	if err != nil {
		t.Fatalf("read generated ipv4 file: %v", err)
	}
	gotHeader := string(header)
	if !strings.Contains(gotHeader, "custom-hosts") || !strings.Contains(gotHeader, "custom-ips") || strings.Contains(gotHeader, "disabled") {
		t.Fatalf("custom source header mismatch:\n%s", gotHeader)
	}
}
