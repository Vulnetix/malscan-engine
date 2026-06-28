package badnet

import "testing"

func TestAddAndHas(t *testing.T) {
	s := NewEmpty()
	s.Add("45.137.21.9")          // real IPv4
	s.Add("2606:4700::1111")      // real IPv6
	s.Add("malware-drop.xyz")     // domain
	s.Add("attacker@evil-c2.ru")  // email
	s.Add("0.0.0.0 evil-host.cc") // addLines would split; Add takes whole → domain invalid, ignored
	s.AddDomain("evil-host.cc")   // explicit
	s.Add("203.0.113.5")          // benign (TEST-NET) → dropped
	s.Add("github.com")           // benign domain → dropped
	s.Add("noreply@github.com")   // benign email host → dropped
	s.Add("1.2.3.0/24")           // CIDR → not a single IP → ignored

	if !s.HasIP("45.137.21.9") {
		t.Error("expected IPv4 hit")
	}
	if !s.HasIP("2606:4700:0000:0000:0000:0000:0000:1111") {
		t.Error("expected IPv6 hit (format-insensitive)")
	}
	if !s.HasDomain("Malware-Drop.XYZ") {
		t.Error("expected domain hit (case-insensitive)")
	}
	if !s.HasDomain("evil-host.cc") {
		t.Error("expected explicit domain hit")
	}
	if !s.HasEmail("Attacker@Evil-C2.ru") {
		t.Error("expected email hit (case-insensitive)")
	}
	if s.HasIP("203.0.113.5") {
		t.Error("benign TEST-NET IP must be dropped")
	}
	if s.HasDomain("github.com") {
		t.Error("benign domain must be dropped")
	}
	if s.HasEmail("noreply@github.com") {
		t.Error("benign-host email must be dropped")
	}
	if s.HasIP("1.2.3.0") {
		t.Error("CIDR network address must not be stored as a single IP")
	}
}

func TestAccessorsSortedAndDeduped(t *testing.T) {
	s := NewEmpty()
	s.AddAll([]string{"45.137.21.9", "45.137.21.9", "9.9.9.10", "1.0.0.9"})
	ips := s.IPs()
	if len(ips) != 3 {
		t.Fatalf("expected 3 deduped IPs, got %d: %v", len(ips), ips)
	}
	for i := 1; i < len(ips); i++ {
		if ips[i-1] > ips[i] {
			t.Errorf("IPs not sorted: %v", ips)
		}
	}
}

func TestEmbeddedLoadDoesNotPanic(t *testing.T) {
	s := New() // exercises //go:embed of data/*.txt
	if s.Len() < 0 {
		t.Fatal("unreachable")
	}
}
