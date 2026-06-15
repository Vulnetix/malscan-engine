package detect

import (
	"fmt"
	"strings"
)

// metadata / maintainer / github-stars / aur-comments — ports of the
// corresponding traur features. These are reputation/risk signals, recorded as
// ClassContext (package metadata) and never minting a CVE on their own.

func analyzeMetadata(ctx *PackageContext) []Finding {
	m := ctx.Meta
	if m == nil {
		return nil
	}
	var out []Finding
	if m.NumVotes == 0 {
		out = append(out, ctxFinding("M-VOTES-ZERO", "metadata", 30, "Package has zero votes"))
	} else if m.NumVotes < 5 {
		out = append(out, ctxFinding("M-VOTES-LOW", "metadata", 20, fmt.Sprintf("Package has very few votes (%d)", m.NumVotes)))
	}
	if m.Popularity == 0.0 {
		out = append(out, ctxFinding("M-POP-ZERO", "metadata", 25, "Popularity is 0 (no recent usage)"))
	}
	if m.Maintainer == "" {
		out = append(out, ctxFinding("M-NO-MAINTAINER", "metadata", 20, "Package is orphaned (no maintainer)"))
	}
	if m.URL == "" {
		out = append(out, ctxFinding("M-NO-URL", "metadata", 15, "No upstream URL provided"))
	}
	if len(m.License) == 0 {
		out = append(out, ctxFinding("M-NO-LICENSE", "metadata", 10, "No license specified"))
	}
	if m.OutOfDate > 0 {
		out = append(out, ctxFinding("M-OUT-OF-DATE", "metadata", 5, "Package is flagged as out of date"))
	}
	return out
}

func analyzeMaintainer(ctx *PackageContext) []Finding {
	m := ctx.Meta
	if m == nil {
		return nil
	}
	var out []Finding
	now := nowUnix()
	pkgs := ctx.MaintainerPackages

	if len(pkgs) == 1 {
		ageDays := (now - m.FirstSubmitted) / 86400
		if ageDays < 30 {
			out = append(out, ctxFinding("B-MAINTAINER-NEW", "behavioral", 30,
				fmt.Sprintf("Maintainer has only 1 package, created %d days ago", ageDays)))
		} else {
			out = append(out, ctxFinding("B-MAINTAINER-SINGLE", "behavioral", 15, "Maintainer has only 1 package"))
		}
	}

	recentCutoff := now - 48*3600
	recent := 0
	for _, p := range pkgs {
		if p.FirstSubmitted >= recentCutoff {
			recent++
		}
	}
	if recent >= 3 {
		out = append(out, ctxFinding("B-MAINTAINER-BATCH", "behavioral", 45,
			fmt.Sprintf("Maintainer created %d packages in the last 48 hours", recent)))
	}
	return out
}

func analyzeGithubStars(ctx *PackageContext) []Finding {
	if ctx.GithubNotFound {
		f := ctxFinding("M-GITHUB-NOT-FOUND", "metadata", 25, "Upstream URL points to GitHub but repo does not exist")
		if ctx.Meta != nil {
			f.MatchedLine = ctx.Meta.URL
		}
		return []Finding{f}
	}
	if ctx.GithubStars != nil {
		stars := *ctx.GithubStars
		if stars == 0 {
			return []Finding{ctxFinding("M-GITHUB-STARS-ZERO", "metadata", 20, "Upstream GitHub repo has 0 stars")}
		} else if stars < 10 {
			return []Finding{ctxFinding("M-GITHUB-STARS-LOW", "metadata", 10, fmt.Sprintf("Upstream GitHub repo has very few stars (%d)", stars))}
		}
	}
	return nil
}

var securityKeywords = []string{
	"malware", "backdoor", "trojan", "keylogger", "cryptominer", "ransomware",
	"rootkit", "compromised", "virus", "suspicious", "malicious", "spyware",
	"unsafe", "dangerous", "phishing", "exploit",
}

func analyzeAurComments(ctx *PackageContext) []Finding {
	for _, comment := range ctx.AurComments {
		lower := strings.ToLower(comment)
		for _, kw := range securityKeywords {
			if strings.Contains(lower, kw) {
				truncated := comment
				if len(truncated) > 120 {
					truncated = truncated[:120] + "..."
				}
				f := ctxFinding("M-COMMENTS-SECURITY", "metadata", 40,
					fmt.Sprintf("AUR comment mentions security concern (keyword: %s)", kw))
				f.MatchedLine = truncated
				return []Finding{f}
			}
		}
	}
	return nil
}
