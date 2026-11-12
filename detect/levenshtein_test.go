package detect

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// Property tests for levenshtein (detect/name.go). It is the B-TYPOSQUAT
// 1-edit gate: a package name one edit away from a popular name mints as
// evidence, so a regression here changes which names become typosquats.

// levenshteinSeeds: ASCII names (drawn from topPackages), accented names,
// empty strings and one-rune strings. They double as fuzz seeds and as a
// source of generated bases.
var levenshteinSeeds = []string{
	"", "a", "z", "é",
	"yay", "paru", "google-chrome", "visual-studio-code-bin", "discord",
	"slack-desktop", "protonvpn", "mullvad-vpn", "tor-browser", "firefox",
	"downgrade", "nerd-fonts-complete", "café", "naïve", "cafe", "naive",
	"日本語", "日本語テキスト", "🚀",
}

// levenshteinRunePool mixes ASCII name characters with multi-byte runes so
// generated strings exercise both byte and rune boundaries.
var levenshteinRunePool = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_éàüñçøåæêâîôû日本語言漢字🚀")

// randomLevenshteinString returns a seed verbatim a quarter of the time and
// otherwise a random 0..11 rune string from levenshteinRunePool.
func randomLevenshteinString(rng *rand.Rand) string {
	if rng.IntN(4) == 0 {
		return levenshteinSeeds[rng.IntN(len(levenshteinSeeds))]
	}
	var sb strings.Builder
	for i := rng.IntN(12); i > 0; i-- {
		sb.WriteRune(levenshteinRunePool[rng.IntN(len(levenshteinRunePool))])
	}
	return sb.String()
}

// runeLevenshtein is a single-row reference edit distance over runes, written
// differently from levenshtein so the cross-check is independent.
func runeLevenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	dp := make([]int, len(rb)+1)
	for j := range dp {
		dp[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		prev := dp[0]
		dp[0] = i
		for j := 1; j <= len(rb); j++ {
			old := dp[j]
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			dp[j] = min(dp[j]+1, dp[j-1]+1, prev+cost)
			prev = old
		}
	}
	return dp[len(rb)]
}

func TestLevenshteinProperties(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))

	t.Run("symmetry", func(t *testing.T) {
		for range 200 {
			a, b := randomLevenshteinString(rng), randomLevenshteinString(rng)
			if got, want := levenshtein(a, b), levenshtein(b, a); got != want {
				t.Fatalf("levenshtein(%q, %q) = %d but reverse = %d", a, b, got, want)
			}
		}
	})

	t.Run("identity", func(t *testing.T) {
		for range 200 {
			a := randomLevenshteinString(rng)
			if got := levenshtein(a, a); got != 0 {
				t.Fatalf("levenshtein(%q, %q) = %d, want 0", a, a, got)
			}
		}
	})

	t.Run("triangle-inequality", func(t *testing.T) {
		for range 200 {
			a, b, c := randomLevenshteinString(rng), randomLevenshteinString(rng), randomLevenshteinString(rng)
			ab, bc, ac := levenshtein(a, b), levenshtein(b, c), levenshtein(a, c)
			if ac > ab+bc {
				t.Fatalf("triangle inequality violated: levenshtein(%q, %q) = %d > %d + %d", a, c, ac, ab, bc)
			}
		}
	})

	t.Run("boundary", func(t *testing.T) {
		for range 200 {
			a := randomLevenshteinString(rng)
			want := len([]rune(a))
			if got := levenshtein("", a); got != want {
				t.Fatalf("levenshtein(%q, %q) = %d, want %d", "", a, got, want)
			}
			if got := levenshtein(a, ""); got != want {
				t.Fatalf("levenshtein(%q, %q) = %d, want %d", a, "", got, want)
			}
		}
	})

	t.Run("one-edit", func(t *testing.T) {
		for range 200 {
			base := []rune(randomLevenshteinString(rng))
			if len(base) == 0 {
				base = []rune("x")
			}

			// Insert one rune at the start, middle and end.
			for _, p := range []int{0, len(base) / 2, len(base)} {
				r := levenshteinRunePool[rng.IntN(len(levenshteinRunePool))]
				ed := append(append([]rune(nil), base[:p]...), r)
				ed = append(ed, base[p:]...)
				if got := levenshtein(string(base), string(ed)); got != 1 {
					t.Fatalf("inserting %q into %q at %d: distance %d, want 1", r, string(base), p, got)
				}
			}

			// Delete one rune.
			p := rng.IntN(len(base))
			ed := append(append([]rune(nil), base[:p]...), base[p+1:]...)
			if got := levenshtein(string(base), string(ed)); got != 1 {
				t.Fatalf("deleting one rune from %q at %d: distance %d, want 1", string(base), p, got)
			}

			// Substitute one rune for a different one.
			p = rng.IntN(len(base))
			r := levenshteinRunePool[rng.IntN(len(levenshteinRunePool))]
			for r == base[p] {
				r = levenshteinRunePool[rng.IntN(len(levenshteinRunePool))]
			}
			ed = append(append([]rune(nil), base[:p]...), r)
			ed = append(ed, base[p+1:]...)
			if got := levenshtein(string(base), string(ed)); got != 1 {
				t.Fatalf("substituting %q into %q at %d: distance %d, want 1", r, string(base), p, got)
			}
		}
	})

	t.Run("rune-not-byte", func(t *testing.T) {
		// é is two bytes, so a byte-based distance would report 2; the
		// rune-based distance is 1.
		if got := levenshtein("café", "cafe"); got != 1 {
			t.Fatalf("levenshtein(%q, %q) = %d, want 1 (rune semantics)", "café", "cafe", got)
		}
		for range 200 {
			a, b := randomLevenshteinString(rng), randomLevenshteinString(rng)
			if got, want := levenshtein(a, b), runeLevenshtein(a, b); got != want {
				t.Fatalf("levenshtein(%q, %q) = %d, rune reference = %d", a, b, got, want)
			}
		}
	})
}

func FuzzLevenshteinNoPanic(f *testing.F) {
	for _, s := range levenshteinSeeds {
		f.Add(s, s)
	}
	f.Add("café", "cafe")
	f.Add("naïve", "naive")
	f.Fuzz(func(t *testing.T, a, b string) {
		levenshtein(a, b)
	})
}
