package badnet

import "testing"

func TestParseFeedFormats(t *testing.T) {
	cases := []struct {
		format, body string
		ips, domains int
	}{
		{"iplist", "# comment\n185.220.101.9\t4\n45.95.147.236\n10.0.0.0/8\n", 2, 0},
		{"hosts", "0.0.0.0 evil-host-1.xyz\nbad-domain-2.top\n", 0, 2},
		{"mixed", "https://phish-login-3.top/login\n185.220.101.4,Possible Cobalt Strike C2 IP\n", 1, 1},
	}
	for _, c := range cases {
		p, err := ParseFeed(c.format, c.body)
		if err != nil {
			t.Fatalf("%s: %v", c.format, err)
		}
		if len(p.IPs) != c.ips || len(p.Domains) != c.domains {
			t.Errorf("%s: got %d IPs %v, %d domains %v; want %d and %d", c.format, len(p.IPs), p.IPs, len(p.Domains), p.Domains, c.ips, c.domains)
		}
	}
	if _, err := ParseFeed("nope", ""); err == nil {
		t.Error("an unknown format must be an error")
	}
}
