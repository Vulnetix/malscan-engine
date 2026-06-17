// Package goodkeys is an ALLOWLIST of known-good cryptographic signing keys (and
// the signing identities/emails that own them) belonging to trusted platform
// INFRASTRUCTURE — most importantly GitHub's "web-flow" GPG key, which signs
// every commit/merge made through the GitHub web UI.
//
// Why this exists: threat-actor enrichment discovers keys and emails from commit
// signatures and the GitHub/GitLab APIs. Some of what it finds is platform
// infrastructure, NOT the human attacker. A commit merged in the GitHub web UI
// is committed by "GitHub <noreply@github.com>" and carries GitHub's own PGP
// signature — attributing that key/identity to a threat actor is a false
// positive. (This was observed live during the AUR "Atomic Arch" npm-payload
// enrichment: a fardewoak merge commit's "-----BEGIN PGP SIGNATURE-----" block
// was GitHub's web-flow signature, and its committer was noreply@github.com.)
//
// Contract: callers MUST consult this allowlist FIRST and short-circuit — do NOT
// run the (expensive, and false-positive-prone) DB / registry / GitHub-API
// actor-key lookup for any token that IsKnownGood/IsKnownGoodEmail returns true
// for. See Set.IsKnownGood.
//
// The list is HARDCODED below with a comment per entry documenting provenance.
// It is also augmentable at runtime via AddKey/AddEmail (e.g. from a curated
// allowlist table) so new platform keys can be added without a code change.
//
// Dependency-free (stdlib only) so it can be lifted into the shared Vulnetix
// detection module and consumed by both the VDB processors and the
// package-firewall.
package goodkeys

import "strings"

// Entry describes one allowlisted signing key and/or identity.
type Entry struct {
	Owner       string // who controls the key, e.g. "GitHub web-flow"
	Kind        string // "gpg" | "ssh"
	Fingerprint string // GPG full 40-hex fingerprint, or SSH "SHA256:..." fingerprint
	KeyID       string // GPG long (16-hex) key id; empty for SSH
	SSHKeyBody  string // base64 body of an SSH public key (the "AAAA..." token); empty for GPG
	Email       string // signing identity email associated with the key, if any
	Note        string // why it is allowlisted / provenance URL
}

// known is the authoritative HARDCODED allowlist of trusted infrastructure keys.
// Add new platform keys here (with a provenance comment) — or at runtime via
// AddKey/AddEmail. Only add keys whose fingerprint is publicly verifiable.
var known = []Entry{
	{
		// GitHub web-flow GPG key. Signs every commit/merge created through the
		// GitHub web UI ("Merge pull request", web editor, squash-merge, the
		// "Verified" badge on web commits). This is the single most common
		// infrastructure key seen on attacker-controlled repos (the attacker
		// merges via the web UI, so the COMMITTER is GitHub, not them).
		// Provenance: https://github.com/web-flow.gpg  (key id 4AEE18F83AFDEB23)
		Owner:       "GitHub web-flow",
		Kind:        "gpg",
		Fingerprint: "5DE3E0509C47EA3CF04A42D34AEE18F83AFDEB23",
		KeyID:       "4AEE18F83AFDEB23",
		Email:       "noreply@github.com",
		Note:        "GitHub web-UI commit/merge signing key; https://github.com/web-flow.gpg",
	},
	{
		// GitHub Actions / github-actions[bot] commit identity. Commits pushed by
		// the built-in GITHUB_TOKEN are authored by this bot; when made via the
		// API they are web-flow-signed (same key above). The bot identity itself
		// is infrastructure, never an attacker.
		// Provenance: https://api.github.com/users/github-actions%5Bbot%5D
		Owner: "GitHub Actions bot",
		Kind:  "gpg",
		Email: "41898282+github-actions[bot]@users.noreply.github.com",
		Note:  "github-actions[bot] commit identity; web-flow signed",
	},
	{
		// Dependabot commit identity. Dependabot opens/merges PRs; web-flow signed.
		// Provenance: https://api.github.com/users/dependabot%5Bbot%5D
		Owner: "GitHub Dependabot bot",
		Kind:  "gpg",
		Email: "49699333+dependabot[bot]@users.noreply.github.com",
		Note:  "dependabot[bot] commit identity; web-flow signed",
	},
	{
		// GitLab web-IDE / web-merge GPG signing key. GitLab signs commits made
		// through its web UI with this key (gitlab@gitlab.com). Same rationale as
		// GitHub web-flow.
		// Provenance: https://gitlab.com/gitlab-org/gitlab/-/issues (web-commit signing)
		Owner: "GitLab web-commit",
		Kind:  "gpg",
		Email: "gitlab@gitlab.com",
		Note:  "GitLab web-UI commit signing identity",
	},
	{
		// Generic noreply identity used by GitHub for users who hide their email.
		// A commit author of "<user>@users.noreply.github.com" is the platform's
		// privacy proxy, not a real attacker email to attribute on its own.
		Owner: "GitHub privacy noreply",
		Kind:  "gpg",
		Email: "noreply@github.com",
		Note:  "GitHub no-reply privacy identity",
	},
}

// Set is the queryable allowlist. The zero value is not usable; construct with New.
type Set struct {
	tokens  map[string]Entry // normalised key tokens -> entry
	emails  map[string]Entry // lowercased emails -> entry
}

// New returns a Set seeded from the hardcoded known list.
func New() *Set {
	s := &Set{tokens: make(map[string]Entry), emails: make(map[string]Entry)}
	for _, e := range known {
		s.add(e)
	}
	return s
}

func (s *Set) add(e Entry) {
	for _, t := range keyTokens(e) {
		s.tokens[t] = e
	}
	if em := normEmail(e.Email); em != "" {
		s.emails[em] = e
	}
}

// AddKey allowlists an additional key at runtime (e.g. from a curated table).
func (s *Set) AddKey(e Entry) { s.add(e) }

// AddEmail allowlists an additional signing-identity email at runtime.
func (s *Set) AddEmail(owner, email string) {
	if em := normEmail(email); em != "" {
		s.emails[em] = Entry{Owner: owner, Email: email, Note: "runtime-allowlisted email"}
	}
}

// IsKnownGood reports whether token matches an allowlisted infrastructure key.
// token may be a GPG fingerprint (40-hex, spaces ok), a GPG long/short key id,
// an SSH "SHA256:..." fingerprint, or a full/partial SSH public key
// ("ssh-ed25519 AAAA..." or just the "AAAA..." body). Callers MUST call this
// (or IsKnownGoodEmail) BEFORE any DB/API actor-key lookup and skip the lookup
// on a hit.
func (s *Set) IsKnownGood(token string) bool {
	_, ok := s.Lookup(token)
	return ok
}

// Lookup returns the matching allowlist Entry for a key token, if any.
func (s *Set) Lookup(token string) (Entry, bool) {
	for _, t := range normalizeQuery(token) {
		if e, ok := s.tokens[t]; ok {
			return e, true
		}
	}
	return Entry{}, false
}

// IsKnownGoodEmail reports whether email is a trusted signing-identity email
// (e.g. noreply@github.com). Same FIRST-check contract as IsKnownGood.
func (s *Set) IsKnownGoodEmail(email string) bool {
	_, ok := s.LookupEmail(email)
	return ok
}

// LookupEmail returns the matching allowlist Entry for an email, if any.
func (s *Set) LookupEmail(email string) (Entry, bool) {
	if em := normEmail(email); em != "" {
		e, ok := s.emails[em]
		return e, ok
	}
	return Entry{}, false
}

// Len returns the number of distinct allowlisted key tokens.
func (s *Set) Len() int { return len(s.tokens) }

// keyTokens returns every normalised token an entry should be indexed under: the
// full GPG fingerprint, its derived long (16) and short (8) key ids, an explicit
// KeyID, and an SSH fingerprint or key body.
func keyTokens(e Entry) []string {
	var out []string
	if fp := normHex(e.Fingerprint); fp != "" {
		out = append(out, fp)
		if len(fp) >= 16 {
			out = append(out, fp[len(fp)-16:]) // long key id
		}
		if len(fp) >= 8 {
			out = append(out, fp[len(fp)-8:]) // short key id
		}
	} else if sfp := normSSHFingerprint(e.Fingerprint); sfp != "" {
		out = append(out, sfp)
	}
	if kid := normHex(e.KeyID); kid != "" {
		out = append(out, kid)
		if len(kid) >= 8 {
			out = append(out, kid[len(kid)-8:])
		}
	}
	if body := sshBody(e.SSHKeyBody); body != "" {
		out = append(out, body)
	}
	return out
}

// normalizeQuery returns the set of normalised tokens a query string could match.
func normalizeQuery(token string) []string {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	var out []string
	// GPG fingerprint / key id (hex, possibly spaced like "5DE3 E050 ...").
	if h := normHex(token); h != "" {
		out = append(out, h)
		if len(h) >= 16 {
			out = append(out, h[len(h)-16:])
		}
		if len(h) >= 8 {
			out = append(out, h[len(h)-8:])
		}
	}
	// SSH SHA256 fingerprint.
	if sfp := normSSHFingerprint(token); sfp != "" {
		out = append(out, sfp)
	}
	// Full or partial SSH public key -> base64 body.
	if body := sshBody(token); body != "" {
		out = append(out, body)
	}
	return out
}

// normHex uppercases and strips spaces/0x; returns "" unless the result is a
// plausible GPG key id/fingerprint (8, 16, or 40 hex chars).
func normHex(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0X")
	s = strings.NewReplacer(" ", "", "\t", "", ":", "").Replace(s)
	if n := len(s); n != 8 && n != 16 && n != 40 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			return ""
		}
	}
	return s
}

// normSSHFingerprint normalises an OpenSSH "SHA256:<base64>" fingerprint.
func normSSHFingerprint(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToUpper(s), "SHA256:") {
		return ""
	}
	return "SHA256:" + strings.TrimSpace(s[len("SHA256:"):])
}

// sshBody extracts the base64 body from a full SSH public key
// ("ssh-ed25519 AAAA... comment") or returns a bare "AAAA..." body as-is.
// Returns "" for anything that is not a plausible SSH key body.
func sshBody(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	fields := strings.Fields(s)
	for _, f := range fields {
		if strings.HasPrefix(f, "AAAA") && len(f) >= 60 {
			return f
		}
	}
	return ""
}

func normEmail(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Trim(s, "<>\"' ")
	if !strings.Contains(s, "@") {
		return ""
	}
	return s
}
