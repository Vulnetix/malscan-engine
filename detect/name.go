package detect

import (
	"fmt"
	"strings"
)

// Name analysis — port of traur src/features/name_analysis/mod.rs.
// Typosquatting and brand impersonation are factual evaluations → evidence.

var impersonationSuffixes = []string{
	"-fix", "-fixed", "-patch", "-patched", "-updated", "-secure", "-plus",
	"-mod", "-modded", "-pro", "-premium", "-free", "-cracked", "-hack",
	"-custom", "-lite",
}

var brandNames = []string{
	"firefox", "chromium", "chrome", "brave", "librewolf", "zen-browser",
	"discord", "slack", "telegram", "signal", "vscode", "code", "steam",
	"spotify", "obsidian", "1password", "bitwarden", "keepass", "vlc", "mpv",
	"neovim", "gimp", "blender", "thunderbird", "protonvpn", "mullvad",
	"nordvpn", "tor-browser",
}

var topPackages = []string{
	"yay", "paru", "google-chrome", "spotify", "visual-studio-code-bin",
	"brave-bin", "discord", "slack-desktop", "zoom", "teams", "librewolf-bin",
	"zen-browser-bin", "firefox", "chromium", "steam", "lutris", "mangohud",
	"gamemode", "proton-ge-custom", "timeshift", "pamac-aur", "octopi",
	"downgrade", "nerd-fonts-complete", "ttf-ms-fonts", "obs-studio", "vlc",
	"mpv", "neovim", "vim", "emacs", "gimp", "blender", "thunderbird",
	"protonvpn", "mullvad-vpn", "nordvpn-bin", "tor-browser",
}

func analyzeName(ctx *PackageContext) []Finding {
	// Established packages (>=10 votes) skip name checks — same as traur.
	if ctx.Meta != nil && ctx.Meta.NumVotes >= 10 {
		return nil
	}

	name := ctx.Name
	var out []Finding

	for _, brand := range brandNames {
		for _, suffix := range impersonationSuffixes {
			imp := brand + suffix
			if name == imp || name == imp+"-bin" || name == imp+"-git" {
				return []Finding{finding(
					"B-NAME-IMPERSONATE", "name", 65,
					fmt.Sprintf("Name '%s' looks like impersonation of '%s' with suspicious suffix", name, brand),
				)}
			}
		}
	}

	for _, top := range topPackages {
		if top == name {
			continue
		}
		if levenshtein(name, top) == 1 {
			out = append(out, finding("B-TYPOSQUAT", "name", 55,
				fmt.Sprintf("Name '%s' is 1 edit(s) away from popular package '%s'", name, top)))
			break
		}
	}

	for _, top := range topPackages {
		if name == top || len(name) <= len(top) {
			continue
		}
		if strings.HasPrefix(name, top) || strings.HasSuffix(name, top) {
			out = append(out, finding("B-TYPOSQUAT", "name", 55,
				fmt.Sprintf("Name '%s' embeds popular package '%s'", name, top)))
			break
		}
	}

	return out
}

// finding builds an evidence Finding for behavioral/name detectors.
func finding(id, category string, points int, desc string) Finding {
	return Finding{
		ID: id, Category: category, Class: ClassEvidence,
		CWE: DefaultMalwareCWE, Points: points, Description: desc,
	}
}

// levenshtein computes the edit distance between a and b.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}
