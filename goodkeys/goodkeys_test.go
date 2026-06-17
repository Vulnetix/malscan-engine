package goodkeys

import "testing"

func TestGitHubWebFlowAllowlisted(t *testing.T) {
	s := New()
	cases := []string{
		"5DE3E0509C47EA3CF04A42D34AEE18F83AFDEB23",       // full fingerprint
		"5DE3 E050 9C47 EA3C F04A 42D3 4AEE 18F8 3AFD EB23", // spaced fingerprint (gpg --fingerprint)
		"4AEE18F83AFDEB23",                                // long key id
		"4aee18f83afdeb23",                                // lowercase long key id
		"3AFDEB23",                                        // short key id
		"0x4AEE18F83AFDEB23",                              // 0x-prefixed
	}
	for _, c := range cases {
		if !s.IsKnownGood(c) {
			t.Errorf("expected GitHub web-flow key to be allowlisted for token %q", c)
		}
	}
	if e, ok := s.Lookup("4AEE18F83AFDEB23"); !ok || e.Owner != "GitHub web-flow" {
		t.Errorf("Lookup owner = %q, ok=%v; want GitHub web-flow", e.Owner, ok)
	}
}

func TestKnownGoodEmails(t *testing.T) {
	s := New()
	good := []string{
		"noreply@github.com",
		"NOREPLY@GitHub.com", // case-insensitive
		"<noreply@github.com>",
		"41898282+github-actions[bot]@users.noreply.github.com",
		"gitlab@gitlab.com",
	}
	for _, e := range good {
		if !s.IsKnownGoodEmail(e) {
			t.Errorf("expected %q to be an allowlisted signing identity", e)
		}
	}
}

func TestAttackerKeyNotAllowlisted(t *testing.T) {
	s := New()
	bad := []string{
		"DEADBEEFDEADBEEF",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICnotarealkeybodyzzzzzzzzzzzzzzzzzzzzzzzz attacker",
	}
	for _, b := range bad {
		if s.IsKnownGood(b) {
			t.Errorf("attacker token %q must NOT be allowlisted", b)
		}
	}
	if s.IsKnownGoodEmail("attacker@evil.example") {
		t.Error("attacker email must not be allowlisted")
	}
}

func TestRuntimeAdd(t *testing.T) {
	s := New()
	body := "AAAAC3NzaC1lZDI1NTE5AAAAITrustedRunnerHostKeyBodyPaddingPaddingPad"
	s.AddKey(Entry{Owner: "Trusted CI", Kind: "ssh", SSHKeyBody: body})
	if !s.IsKnownGood(body) {
		t.Error("runtime-added SSH key body should be allowlisted")
	}
	if !s.IsKnownGood("ssh-ed25519 " + body + " ci@host") {
		t.Error("full SSH key line should resolve to the allowlisted body")
	}
	s.AddEmail("Trusted CI", "ci-bot@trusted.example")
	if !s.IsKnownGoodEmail("ci-bot@trusted.example") {
		t.Error("runtime-added email should be allowlisted")
	}
}
