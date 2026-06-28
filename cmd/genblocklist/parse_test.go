package main

import (
	"sort"
	"strings"
	"testing"
)

func has(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestParseIPList(t *testing.T) {
	// dshield/alienvault/bruteforceblocker-style: IP first, varied trailing columns.
	body := strings.Join([]string{
		"# comment line",
		"45.137.21.9",
		"185.225.74.12\t# 2026-01-02 42",  // bruteforceblocker
		"23.225.52.67#4#2#...",            // alienvault.data
		"203.0.113.7  # TEST-NET, benign", // allow-filtered
		"8.8.8.8",                         // benign resolver
		"1.2.3.0/24",                      // CIDR range -> skipped
		"62.84.102.85/32",                 // /32 -> kept as single IP
		";semicolon comment",
	}, "\n")
	ex := parseFeed(fmtIPList, body)
	for _, want := range []string{"45.137.21.9", "185.225.74.12", "23.225.52.67", "62.84.102.85"} {
		if !has(ex.ipv4, want) {
			t.Errorf("iplist: expected %s, got %v", want, ex.ipv4)
		}
	}
	for _, bad := range []string{"203.0.113.7", "8.8.8.8", "1.2.3.0"} {
		if has(ex.ipv4, bad) {
			t.Errorf("iplist: %s should be excluded, got %v", bad, ex.ipv4)
		}
	}
}

func TestParseHosts(t *testing.T) {
	body := strings.Join([]string{
		"# Title: AntiMalwareHosts",
		"0.0.0.0 evil-malware.cc",
		"127.0.0.1 phish.example.io",
		"0.0.0.0 github.com", // benign -> dropped
		"bare-domain.biz",    // bare domain line
	}, "\n")
	ex := parseFeed(fmtHosts, body)
	for _, want := range []string{"evil-malware.cc", "phish.example.io", "bare-domain.biz"} {
		if !has(ex.domains, want) {
			t.Errorf("hosts: expected %s, got %v", want, ex.domains)
		}
	}
	if has(ex.domains, "github.com") {
		t.Errorf("hosts: github.com should be dropped, got %v", ex.domains)
	}
	if len(ex.ipv4) != 0 {
		t.Errorf("hosts: sink IPs must not be collected, got %v", ex.ipv4)
	}
}

func TestParseNetsetSkipsCIDR(t *testing.T) {
	body := strings.Join([]string{
		"# firehol_level3",
		"104.244.42.1",
		"45.0.0.0/8",     // huge range -> skipped
		"62.84.102.0/24", // range -> skipped
		"23.225.52.67",
	}, "\n")
	ex := parseFeed(fmtNetset, body)
	if !has(ex.ipv4, "104.244.42.1") || !has(ex.ipv4, "23.225.52.67") {
		t.Errorf("netset: expected single IPs, got %v", ex.ipv4)
	}
	for _, bad := range []string{"45.0.0.0", "62.84.102.0"} {
		if has(ex.ipv4, bad) {
			t.Errorf("netset: CIDR network %s must be skipped, got %v", bad, ex.ipv4)
		}
	}
}

func TestParseRSS(t *testing.T) {
	body := `<?xml version="1.0"?><rss><channel>
<item><title>185.100.157.127</title><description>Suspicious host bad-actor.top seen</description></item>
<item><title><![CDATA[206.196.111.47]]></title></item>
</channel></rss>`
	ex := parseFeed(fmtRSS, body)
	if !has(ex.ipv4, "185.100.157.127") || !has(ex.ipv4, "206.196.111.47") {
		t.Errorf("rss: expected IPs from XML text, got %v", ex.ipv4)
	}
	if !has(ex.domains, "bad-actor.top") {
		t.Errorf("rss: expected domain from description, got %v", ex.domains)
	}
}

func TestParseEmails(t *testing.T) {
	body := strings.Join([]string{
		"# phishing reply addresses",
		"scammer@evil-c2.ru",
		"Fraud@Bad-Actor.net",
		"noreply@github.com", // benign host -> dropped
		"not-an-email",
	}, "\n")
	ex := parseFeed(fmtEmails, body)
	want := []string{"scammer@evil-c2.ru", "fraud@bad-actor.net"}
	sort.Strings(ex.emails)
	for _, w := range want {
		if !has(ex.emails, w) {
			t.Errorf("emails: expected %s, got %v", w, ex.emails)
		}
	}
	if has(ex.emails, "noreply@github.com") {
		t.Errorf("emails: benign-host email should be dropped, got %v", ex.emails)
	}
}

func TestParseMixed(t *testing.T) {
	// isc intelfeed: IPs and domains intermixed.
	body := strings.Join([]string{
		"104.244.42.1",
		"malware-drop.xyz",
		"github.com", // benign domain dropped
		"8.8.8.8",    // benign IP dropped
	}, "\n")
	ex := parseFeed(fmtMixed, body)
	if !has(ex.ipv4, "104.244.42.1") {
		t.Errorf("mixed: expected IP, got %v", ex.ipv4)
	}
	if !has(ex.domains, "malware-drop.xyz") {
		t.Errorf("mixed: expected domain, got %v", ex.domains)
	}
	if has(ex.domains, "github.com") || has(ex.ipv4, "8.8.8.8") {
		t.Errorf("mixed: benign values must be dropped (domains=%v ipv4=%v)", ex.domains, ex.ipv4)
	}
}
