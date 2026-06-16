package detect

import "strings"

// DefaultMalwareCWE is attached to every malicious AUR package, matching the
// existing AUR backfill convention (.repo/backfill_aur_malware.py).
const DefaultMalwareCWE = "CWE-506" // Embedded Malicious Code

// cweForSignal maps a detection signal id to a more specific CWE where one is
// clearly applicable, falling back to CWE-506 (Embedded Malicious Code).
func cweForSignal(id string) string {
	// Normalise the install-script ("IS-") prefix before matching.
	base := strings.TrimPrefix(id, "IS-")
	switch {
	case strings.Contains(base, "SSH-ACCESS"),
		strings.Contains(base, "BROWSER-DATA"),
		strings.Contains(base, "GPG-ACCESS"),
		strings.Contains(base, "PASSWD-READ"),
		strings.Contains(base, "CLIPBOARD-READ"),
		strings.Contains(base, "ENV-TOKEN-ACCESS"),
		strings.Contains(base, "CRYPTO-WALLET"):
		return "CWE-522" // Insufficiently Protected Credentials / sensitive data theft
	case strings.Contains(base, "DISCORD-WEBHOOK"),
		strings.Contains(base, "CURL-POST-DATA"),
		strings.Contains(base, "DNS-EXFIL"),
		strings.Contains(base, "ENV-EXFIL"),
		strings.Contains(base, "SYSINFO-RECON"):
		return "CWE-200" // Exposure of Sensitive Information
	case strings.Contains(base, "REVSHELL"),
		strings.Contains(base, "DEV-UDP"),
		strings.Contains(base, "BINDSHELL"),
		strings.Contains(base, "EVAL-DECODE"),
		strings.Contains(base, "NEW-FUNCTION"),
		strings.Contains(base, "DYNAMIC-REQUIRE"),
		strings.Contains(base, "NODE-EVAL"),
		strings.Contains(base, "CHILDPROC-DECODE"),
		strings.Contains(base, "EXEC-DECODE"),
		strings.Contains(base, "COMPILE-EXEC"),
		strings.Contains(base, "DYNAMIC-IMPORT-DECODE"),
		strings.Contains(base, "OPEN-PIPE"),
		strings.Contains(base, "PROCESS-EXEC"),
		strings.Contains(base, "BUILD-SHELL"):
		return "CWE-94" // Improper Control of Generation of Code (dynamic code execution / command injection)
	case strings.Contains(base, "MINER"),
		strings.Contains(base, "STRATUM"),
		strings.Contains(base, "MINING-POOL"):
		return "CWE-400" // Uncontrolled Resource Consumption (cryptojacking)
	}
	return DefaultMalwareCWE
}
