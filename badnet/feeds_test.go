package badnet

import (
	"fmt"
	"strings"
	"testing"
)

// TestParseFeedConfig pins the feeds.json config-parser contract: parser name
// mapping, skips, and the error branches of parseFeedConfig.
func TestParseFeedConfig(t *testing.T) {
	t.Run("mapsEachParserName", func(t *testing.T) {
		parsers := []struct {
			name   string
			format format
		}{
			{"iplist", fmtIPList},
			{"netset", fmtNetset},
			{"hosts", fmtHosts},
			{"rss", fmtRSS},
			{"emails", fmtEmails},
			{"mixed", fmtMixed},
			{"misp", fmtMISP},
		}
		var body strings.Builder
		body.WriteString(`{"feeds": [`)
		for i, p := range parsers {
			if i > 0 {
				body.WriteString(",")
			}
			fmt.Fprintf(&body, `{"key": "feed-%s", "url": "https://example.test/%s", "parser": "%s", "enabled": true}`, p.name, p.name, p.name)
		}
		body.WriteString(`]}`)

		feeds, err := parseFeedConfig([]byte(body.String()))
		if err != nil {
			t.Fatalf("parseFeedConfig: %v", err)
		}
		if len(feeds) != len(parsers) {
			t.Fatalf("got %d feeds, want %d", len(feeds), len(parsers))
		}
		for i, p := range parsers {
			if feeds[i].name != "feed-"+p.name || feeds[i].format != p.format {
				t.Errorf("feed %d = %q/%q, want %q/%q", i, feeds[i].name, feeds[i].format, "feed-"+p.name, p.format)
			}
		}
	})

	t.Run("skipsDisabledEmptyKeyAndEmptyURL", func(t *testing.T) {
		body := `{
			"feeds": [
				{"key": "kept", "url": "https://example.test/iplist.txt", "parser": "iplist", "enabled": true},
				{"key": "no-enabled-field", "url": "https://example.test/hosts.txt", "parser": "hosts"},
				{"key": "disabled", "url": "https://example.test/disabled.txt", "parser": "iplist", "enabled": false},
				{"key": "", "url": "https://example.test/empty-key.txt", "parser": "iplist"},
				{"key": "empty-url", "url": "", "parser": "iplist"}
			]
		}`
		feeds, err := parseFeedConfig([]byte(body))
		if err != nil {
			t.Fatalf("parseFeedConfig: %v", err)
		}
		if len(feeds) != 2 {
			t.Fatalf("got %d feeds, want the enabled and enabled-by-default entries only: %+v", len(feeds), feeds)
		}
		if feeds[0].name != "kept" || feeds[1].name != "no-enabled-field" {
			t.Errorf("kept feeds = %q, %q; want kept, no-enabled-field", feeds[0].name, feeds[1].name)
		}
	})

	t.Run("unknownParserNamesKey", func(t *testing.T) {
		body := `{"feeds": [{"key": "bogus-feed", "url": "https://example.test/x", "parser": "yaml"}]}`
		_, err := parseFeedConfig([]byte(body))
		if err == nil {
			t.Fatal("expected an error for an unknown parser")
		}
		if !strings.Contains(err.Error(), "bogus-feed") {
			t.Errorf("error %q does not name the feed key", err)
		}
	})

	t.Run("noEnabledFeeds", func(t *testing.T) {
		for name, body := range map[string]string{
			"all disabled": `{"feeds": [{"key": "a", "url": "u", "parser": "iplist", "enabled": false}]}`,
			"empty list":   `{"feeds": []}`,
		} {
			_, err := parseFeedConfig([]byte(body))
			if err == nil || !strings.Contains(err.Error(), "no enabled feeds") {
				t.Errorf("%s: got err %v, want %q", name, err, "no enabled feeds")
			}
		}
	})

	t.Run("malformedJSON", func(t *testing.T) {
		_, err := parseFeedConfig([]byte(`{"feeds": [`))
		if err == nil {
			t.Fatal("expected an error for malformed JSON")
		}
	})
}

// TestLoadConfiguredFeedsEmbedded pins the fallback contract: the embedded
// data/feeds.json must parse to a non-empty list without error.
func TestLoadConfiguredFeedsEmbedded(t *testing.T) {
	feeds := loadConfiguredFeeds()
	if len(feeds) == 0 {
		t.Fatal("embedded data/feeds.json should load a non-empty feed list")
	}
	for _, f := range feeds {
		if f.name == "" || f.url == "" {
			t.Errorf("feed %+v missing name or url", f)
		}
		if f.format == "" {
			t.Errorf("feed %q has no format", f.name)
		}
	}
}
