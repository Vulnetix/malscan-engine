package badnet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// newFeedServer starts an in-memory origin for badnet fetch tests: each request
// path in bodies is served verbatim, any other path returns 404 (a fetch error
// for FetchWithFeedsFile). The server is closed via t.Cleanup.
func newFeedServer(t *testing.T, bodies map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// feedEntry is one source in a feeds.json fixture.
type feedEntry struct {
	key     string
	path    string
	parser  string
	enabled bool
}

// writeFeedsFile writes a feeds.json whose feeds point at srv and returns its
// path. The shape matches what parseFeedConfig reads in feeds.go.
func writeFeedsFile(t *testing.T, srv *httptest.Server, entries ...feedEntry) string {
	t.Helper()
	srcs := make([]feedConfigSource, 0, len(entries))
	for _, e := range entries {
		enabled := e.enabled
		srcs = append(srcs, feedConfigSource{
			Key:     e.key,
			URL:     srv.URL + e.path,
			Parser:  e.parser,
			Enabled: &enabled,
		})
	}
	b, err := json.MarshalIndent(feedConfigFile{SchemaVersion: "badnet-feeds/v1", Feeds: srcs}, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "feeds.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
