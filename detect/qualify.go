package detect

import "strings"

// Intent classifies WHY a finding is malicious: the strength of the malicious
// claim and the kind of evidence it represents. It is the "qualification" the
// advisory carries so a human (or downstream consumer) can differentiate a
// genuinely malicious usage from a benign one — the intent of the usage is
// necessary to tell exfiltration from telemetry, persistence from setup, a
// reverse shell from a debug harness.
//
// Intent is derived from the signal id (and, where relevant, the surface it
// fired on) via Qualify. It is advisory metadata: it does NOT change the
// mint/verdict logic (Class still gates that). It lets the processor annotate
// every finding in a malware advisory with the documented bad-actor behaviour
// and the benign-vs-malicious differentiator.
type Intent string

const (
	// IntentMalicious is an unambiguous malicious-code indicator. There is no
	// benign reason for the construct in a package's build/install surface
	// (reverse shell, curl|sh, .onion C2, known-bad hash). Differentiator: the
	// construct itself is the abuse.
	IntentMalicious Intent = "malicious"
	// IntentExfil is a data-theft indicator: credential/env harvest + network
	// egress, or an exfil-channel URL. Differentiator: a benign package may read
	// an env var or contact a registry, but reading secrets AND sending them
	// off-host in an install hook is exfiltration.
	IntentExfil Intent = "exfiltration"
	// IntentPersistence is a persistence/establishment indicator: profile
	// modification, systemd/cron/autostart, registry-native install hooks that
	// survive beyond the package. Differentiator: a benign installer may write a
	// desktop entry, but modifying shell profiles / cron / global install hooks
	// from a package's install surface is establishment.
	IntentPersistence Intent = "persistence"
	// IntentObfuscation is a defence-evasion indicator: base64/hex/rot13 decode
	// chained into an executor, $IFS splitting, history clearing. Differentiator:
	// a benign package may decode a base64 asset, but decoding a payload INTO an
	// executor (eval/exec/system) is evasion.
	IntentObfuscation Intent = "obfuscation"
	// IntentRecon is a discovery indicator: system-info gathering + network.
	IntentRecon Intent = "reconnaissance"
	// IntentDualUse is a dual-use tool/command. It is malicious ONLY in an
	// auto-execution surface (install hook or PKGBUILD build()) and is
	// corroboration elsewhere. Differentiator: the SURFACE (does it auto-run at
	// install/build?) plus a compounding signal decides benign vs malicious.
	IntentDualUse Intent = "dual-use"
	// IntentReputation is a reputation/risk signal (newness, missing checksum,
	// typosquat). Never mints alone; recorded as context.
	IntentReputation Intent = "reputation"
)

// Qualification is the encoded deep-research metadata for one signal: the
// documented bad-actor behaviour it captures, the benign-vs-malicious
// differentiator (the INTENT test), and a coarse ATT&CK-style tactic. It is the
// "what makes this qualified" a human reviewer needs to triage a finding.
type Qualification struct {
	Signal         string
	Intent         Intent
	Tactic         string // ATT&CK-style tactic (e.g. "TA0002 Execution", "TA0010 Exfiltration")
	Behavior       string // the documented bad-actor behaviour this captures
	Differentiator string // the test that separates benign from malicious usage
}

// qualRegistry maps a signal id (after stripping the "IS-" install-script
// prefix) to its Qualification. Signals absent here return a default
// (IntentDualUse / CWE-506) so every finding carries SOME intent label.
//
// The behaviour and differentiator text is distilled from documented
// supply-chain malware TTPs (OSS Index/OpenSSF malicious-package advisories,
// Aqua/Socket/Snyk supply-chain write-ups, MITRE ATT&CK). The registry is the
// single place the engine records WHY each indicator is malicious — the
// processor folds it into the advisory detail.
var qualRegistry = map[string]Qualification{
	// ── Download-and-execute (override gates) ─────────────────────────────────
	"P-CURL-PIPE":          {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "curl output piped to a shell — fetches and runs remote code at build/install time", Differentiator: "no legitimate package pipes a downloader straight into an interpreter; a benign build downloads to a file and verifies it first"},
	"P-WGET-PIPE":          {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "wget output piped to a shell", Differentiator: "same as P-CURL-PIPE — download-and-execute is never a benign install step"},
	"P-CURL-PIPE-PYTHON":   {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "curl piped to the Python interpreter", Differentiator: "a benign package pins a dependency version; piping a remote blob into python is staged execution"},
	"P-CURL-PIPE-PERL":     {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "curl piped to Perl", Differentiator: "no benign installer pipes a downloader into perl"},
	"P-WGET-PIPE-PYTHON":   {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "wget piped to Python", Differentiator: "no benign installer pipes a downloader into python"},
	"P-SOURCE-REMOTE":      {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "sources a remote script via process substitution", Differentiator: "benign builds vendor or pin a source URL; sourcing `<(curl …)` runs unverified remote code"},
	"P-PYTHON-EXEC-URL":    {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "Python exec() of a URL fetch (fetch-and-execute)", Differentiator: "exec(urlopen(...)) runs remote code; a benign package imports a pinned dependency"},
	"P-RUBY-EXEC-URL":      {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "Ruby fetch-and-execute (Net::HTTP + eval/exec/system)", Differentiator: "fetching remote code and eval'ing it is staged execution, not a dependency load"},
	"P-PERL-EXEC-URL":      {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "Perl LWP/HTTP::Tiny fetch + system/exec", Differentiator: "fetching and executing remote code is never a benign build step"},
	"P-DEV-UDP":            {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "Bash /dev/udp network connection (C2 channel)", Differentiator: "a benign package never opens a raw UDP socket via /dev/udp; that is a C2 primitive"},
	// ── Reverse / bind shells (override gates) ───────────────────────────────
	"P-REVSHELL-DEVTCP":    {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "Bash reverse shell via /dev/tcp", Differentiator: "/dev/tcp connect-back is a reverse shell primitive with no benign use in a package"},
	"P-REVSHELL-NC":        {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "Netcat reverse shell (-e/-c)", Differentiator: "nc -e/-c connects a shell to a remote host; no benign installer does this"},
	"P-REVSHELL-SOCAT":     {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "Socat reverse shell (TCP + EXEC)", Differentiator: "socat bridging a shell to TCP is a reverse shell"},
	"P-REVSHELL-PYTHON":    {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "Python socket.connect + subprocess reverse shell", Differentiator: "connect-back + subprocess is a reverse shell, not networking code"},
	"P-REVSHELL-PERL":      {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "Perl Socket connect + exec reverse shell", Differentiator: "a connect-back shell in Perl has no benign packaging use"},
	"P-REVSHELL-RUBY":      {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "Ruby TCPSocket reverse shell", Differentiator: "TCPSocket connect-back with exec is a reverse shell"},
	"P-REVSHELL-AWK":       {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "Awk /inet/tcp reverse shell", Differentiator: "awk opening /inet/tcp is a reverse shell primitive"},
	"P-REVSHELL-LUA":       {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "Lua socket.tcp connect reverse shell", Differentiator: "Lua connect-back is a reverse shell"},
	"P-REVSHELL-PHP":       {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "PHP fsockopen/socket_connect reverse shell", Differentiator: "PHP connect-back is a reverse shell"},
	"G-REVSHELL-NODE":      {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "Node.js net.Socket reverse shell", Differentiator: "node -e with net.Socket connect-back is a reverse shell, not app networking"},
	"G-REVSHELL-OPENSSL":   {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "openssl s_server encrypted C2 listener", Differentiator: "running an TLS server in an install hook is a bind shell / C2 listener"},
	"G-PIPE":              {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "download utility (curl/wget/aria2c/lwp…) piped into an interpreter/shell — fetch-and-execute", Differentiator: "piping a downloader into an interpreter runs unverified remote code; a benign package downloads to a file and verifies first"},
	"G-ALT-PIPE":           {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "alternative downloader (aria2c/lwp/finger/tftp/smbclient) piped to a shell", Differentiator: "piping an alternative downloader into a shell is download-and-execute evasion"},
	"G-BINDSHELL-NC":       {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "Netcat bind shell (listen + exec)", Differentiator: "nc -l -e binds a shell to a port; no benign installer does this"},
	// ── Exfiltration / C2 channels ───────────────────────────────────────────
	"P-DISCORD-WEBHOOK":    {Intent: IntentExfil, Tactic: "TA0010 Exfiltration", Behavior: "Discord webhook URL used as a data-exfil channel", Differentiator: "a webhook destination in install code is an exfil channel; a benign package links to docs, not a webhook endpoint"},
	"P-TELEGRAM-BOT":       {Intent: IntentExfil, Tactic: "TA0010 Exfiltration", Behavior: "Telegram bot API URL (exfil/C2 channel)", Differentiator: "a bot API URL in build/install code is an exfil channel"},
	"P-CURL-POST-DATA":     {Intent: IntentExfil, Tactic: "TA0010 Exfiltration", Behavior: "curl POST of a variable (exfil host data)", Differentiator: "POSTing variable data from an install hook is exfiltration; a benign installer never POSTs runtime data"},
	"P-DNS-EXFIL":          {Intent: IntentExfil, Tactic: "TA0010 Exfiltration", Behavior: "DNS lookup with variable interpolation (DNS exfil)", Differentiator: "dig/nslookup of a variable encodes data in DNS; a benign package resolves fixed hosts"},
	"P-JS-ENV-EXFIL":       {Intent: IntentExfil, Tactic: "TA0010 Exfiltration", Behavior: "JSON.stringify(process.env) (credential/secret harvest)", Differentiator: "serialising the whole env is recon for exfil; a benign package reads specific vars"},
	"P-NPM-HOOK-ENV-EXFIL": {Intent: IntentExfil, Tactic: "TA0010 Exfiltration", Behavior: "lifecycle install hook reads process.env and contacts the network", Differentiator: "reading secrets AND egressing in an install hook is exfiltration; a benign hook may read ONE config var but never ships env off-host"},
	"P-PY-ENV-EXFIL":       {Intent: IntentExfil, Tactic: "TA0010 Exfiltration", Behavior: "Python reads env/host info and contacts the network", Differentiator: "env read + network in setup.py is recon/exfil; benign setup reads only build config"},
	"P-ENV-TOKEN-ACCESS":   {Intent: IntentExfil, Tactic: "TA0010 Exfiltration", Behavior: "accesses a named secret env var (AWS/GITHUB/NPM token…)", Differentiator: "a benign package never references cloud-provider token env names in build code"},
	"P-CLIPBOARD-READ":     {Intent: IntentExfil, Tactic: "TA0010 Exfiltration", Behavior: "clipboard read (credential theft)", Differentiator: "no benign installer reads the clipboard"},
	// ── Credential / sensitive-file access ───────────────────────────────────
	"P-SSH-ACCESS":         {Intent: IntentMalicious, Tactic: "TA0006 Credential Access", Behavior: "reads ~/.ssh (private key theft)", Differentiator: "a benign package never touches a user's SSH directory"},
	"P-GPG-ACCESS":         {Intent: IntentMalicious, Tactic: "TA0006 Credential Access", Behavior: "reads ~/.gnupg (keyring theft)", Differentiator: "no benign installer reads the GPG keyring"},
	"P-BROWSER-DATA":       {Intent: IntentMalicious, Tactic: "TA0006 Credential Access", Behavior: "reads browser profile data (saved creds/cookies)", Differentiator: "no benign installer reads browser profiles"},
	"P-PASSWD-READ":        {Intent: IntentMalicious, Tactic: "TA0006 Credential Access", Behavior: "reads /etc/passwd or /etc/shadow", Differentiator: "a package reading the system password file is credential access"},
	// ── Persistence ──────────────────────────────────────────────────────────
	"P-PROFILE-MOD":        {Intent: IntentPersistence, Tactic: "TA0003 Persistence", Behavior: "appends to a shell profile (~/.bashrc/.zshrc) — runs on every shell", Differentiator: "a benign installer never modifies the user's shell profile; that is persistence"},
	"P-CRON-CREATE":        {Intent: IntentPersistence, Tactic: "TA0003 Persistence", Behavior: "creates a cron job", Differentiator: "scheduling from an install hook is persistence; benign packages don't install cron entries"},
	"P-SYSTEMD-CREATE":     {Intent: IntentPersistence, Tactic: "TA0003 Persistence", Behavior: "enables/installs a systemd service", Differentiator: "a package enabling a systemd unit at install is persistence (context: legitimate daemons do this via distro packaging, not AUR/registry hooks)"},
	"P-XDG-AUTOSTART":      {Intent: IntentPersistence, Tactic: "TA0003 Persistence", Behavior: "XDG autostart entry (runs at login)", Differentiator: "writing an autostart entry from an install hook is persistence"},
	"P-PROMPT-COMMAND":     {Intent: IntentPersistence, Tactic: "TA0003 Persistence", Behavior: "sets PROMPT_COMMAND (runs on every prompt)", Differentiator: "PROMPT_COMMAND injection is persistence/re-exec; no benign installer sets it"},
	"P-LD-PRELOAD":         {Intent: IntentPersistence, Tactic: "TA0003 Persistence", Behavior: "sets LD_PRELOAD (library injection on every exec)", Differentiator: "LD_PRELOAD in an install hook is rootkit-style persistence"},
	// ── Obfuscation / defence evasion ────────────────────────────────────────
	"P-EVAL-BASE64":        {Intent: IntentObfuscation, Tactic: "TA0005 Defense Evasion", Behavior: "eval of a base64-decoded payload", Differentiator: "decoding a blob INTO eval is obfuscated execution; a benign package decodes assets, not code"},
	"P-BASE64":             {Intent: IntentObfuscation, Tactic: "TA0005 Defense Evasion", Behavior: "base64 -d (possible payload hiding)", Differentiator: "decoding alone is dual-use (icons/certs); it becomes malicious when chained into an executor (see P-EVAL-BASE64)"},
	"P-IFS-OBFUSCATION":    {Intent: IntentObfuscation, Tactic: "TA0005 Defense Evasion", Behavior: "$IFS used as a command separator", Differentiator: "$IFS splitting hides the command boundary; no benign installer needs it"},
	"P-ANSI-C-HEX":         {Intent: IntentObfuscation, Tactic: "TA0005 Defense Evasion", Behavior: "ANSI-C $'\\xNN' hex quoting of command strings", Differentiator: "hex-quoting command strings is evasion; benign scripts quote plainly"},
	"P-ROT13":              {Intent: IntentObfuscation, Tactic: "TA0005 Defense Evasion", Behavior: "ROT13 of a payload", Differentiator: "ROT13 in an install hook is payload obfuscation; benign packages never need it"},
	"P-REV-EXEC":           {Intent: IntentObfuscation, Tactic: "TA0005 Defense Evasion", Behavior: "reversed string piped to a shell", Differentiator: "reversing a command string is evasion"},
	"P-HISTORY-CLEAR":      {Intent: IntentObfuscation, Tactic: "TA0005 Defense Evasion", Behavior: "clears shell history (HISTFILE unset / history -c)", Differentiator: "an installer clearing history is hiding activity; benign installs never do this"},
	"P-LOG-CLEAR":          {Intent: IntentObfuscation, Tactic: "TA0005 Defense Evasion", Behavior: "clears /var/log", Differentiator: "truncating system logs from an install hook is anti-forensics"},
	// ── Cryptocurrency mining / cryptojacking ────────────────────────────────
	"P-MINER-BINARY":       {Intent: IntentMalicious, Tactic: "TA0040 Impact", Behavior: "references crypto-mining software (xmrig et al.)", Differentiator: "a package bundling a miner is cryptojacking; benign packages never ship miners"},
	"P-STRATUM-URL":        {Intent: IntentMalicious, Tactic: "TA0040 Impact", Behavior: "Stratum mining-protocol URL", Differentiator: "a Stratum URL is a mining pool connection; no benign package uses Stratum"},
	"P-MINING-POOL":        {Intent: IntentMalicious, Tactic: "TA0040 Impact", Behavior: "known mining-pool domain", Differentiator: "a mining pool domain in install code is cryptojacking"},
	// ── Reputation / context (never mint alone) ──────────────────────────────
	"P-NO-CHECKSUMS":       {Intent: IntentReputation, Tactic: "context", Behavior: "no integrity checksum array in the build script", Differentiator: "missing checksums are a supply-chain risk signal (MITM-able source), not proof of malice — many legit PKGBUILDs omit them"},
	"P-HTTP-SOURCE":        {Intent: IntentReputation, Tactic: "context", Behavior: "plain-HTTP source URL (no TLS)", Differentiator: "a MITM risk signal, not malice; many legacy sources still use HTTP — record as context"},
	"P-RAW-IP-URL":         {Intent: IntentReputation, Tactic: "context", Behavior: "source URL uses a raw IP", Differentiator: "an IP source is a risk signal (no DNS accountability); context only"},
	"B-TYPOSQUAT":          {Intent: IntentReputation, Tactic: "context", Behavior: "package name embeds a popular package name (typosquat/brandjack candidate)", Differentiator: "name similarity alone is not malice — confirm with a compounding signal (new maintainer + code exec); context only"},
	// ── IOC / known-bad infrastructure ───────────────────────────────────────
	"IOC-STIX-MATCH":       {Intent: IntentMalicious, Tactic: "TA0011 Command & Control", Behavior: "package source references a known-bad C2/exfil domain/IP/URL from the Vulnetix STIX feed", Differentiator: "an exact match to catalogued malicious infrastructure is factual evidence; a benign package referencing the same host would itself be suspicious"},
	"B-KNOWN-BAD-HASH":     {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "a declared/source artifact hash matches a known-bad hash", Differentiator: "an exact hash match to a catalogued malicious artifact is factual evidence"},
	// ── Combination-gate triggers (corroboration, never mint alone) ──────────
	"SA-HIGH-ENTROPY-HEREDOC": {Intent: IntentDualUse, Tactic: "TA0005 Defense Evasion", Behavior: "high-entropy heredoc payload (possible encoded blob)", Differentiator: "entropy alone is dual-use (legit base64 icons/certs/fonts); it mints only with a compounding ownership/identity trigger"},
	"MT-OWNERSHIP-TRANSFER":  {Intent: IntentReputation, Tactic: "context", Behavior: "established owner replaced by a different current owner", Differentiator: "hand-offs happen legitimately; a takeover mints only alongside a corroborating payload/evidence finding"},
	"MT-ORPHAN-ADOPTION":     {Intent: IntentReputation, Tactic: "context", Behavior: "original submitter gone, a different account now maintains the package", Differentiator: "orphan adoptions are usually benign; mints only with a corroborating payload/evidence finding"},
	"MT-OWNER-KNOWN-BAD":     {Intent: IntentReputation, Tactic: "TA0001 Initial Access", Behavior: "current owner matches a catalogued ThreatActor", Differentiator: "strongest ownership signal, but still reputation, not code — mints ONLY with a corroborating payload/evidence finding, never alone"},

	// ── Registry-native behaviour TTPs (behaviors.go) ───────────────────────
	// Multi-line/sequence behaviours the single-line pattern DB cannot capture.
	// Each is emitted with its qualification in the Description; these entries
	// make the structured Qualification retrievable by signal id.
	"GEM-GLOBAL-INSTALL-HOOK":      {Intent: IntentPersistence, Tactic: "TA0003 Persistence", Behavior: "RubyGems gem registers a global Gem.post_install_hooks/pre_install_hooks entry that runs on every future gem install", Differentiator: "the global-hook API is for installers/tooling, not published gems — a benign gem never registers a global install hook"},
	"PY-PTH-AUTOIMPORT-PERSISTENCE": {Intent: IntentPersistence, Tactic: "TA0003 Persistence", Behavior: "setup.py writes a .pth file carrying an import statement; Python auto-runs .pth import lines at interpreter start", Differentiator: "benign .pth files only append paths to sys.path — they never contain import statements"},
	"JS-HOOK-DECODE-EGRESS-SEQ":    {Intent: IntentExfil, Tactic: "TA0010 Exfiltration", Behavior: "npm lifecycle hook decodes a payload (atob/Buffer.from) AND opens a network egress — the canonical install-time exfil/staged-execution sequence", Differentiator: "a benign hook may decode an asset OR contact a registry, but decode+egress together in an install hook is exfiltration/staging"},
	"PY-SETUP-CRED-EXFIL":          {Intent: IntentExfil, Tactic: "TA0010 Exfiltration", Behavior: "setup.py opens a credential file (~/.aws/credentials, ~/.ssh/id_rsa, ~/.docker/config.json, ~/.netrc, ~/.pypirc) AND contacts the network", Differentiator: "a benign setup.py never reads credential stores; reading one AND egressing is theft"},
	"CARGO-CONFIG-PERSISTENCE":      {Intent: IntentPersistence, Tactic: "TA0003 Persistence", Behavior: "build.rs writes the global ~/.cargo/config.toml (credential helper / registry replace / git-fetch-with-cli) to hijack future fetches", Differentiator: "a benign build.rs never rewrites the global cargo config"},
	"NUGET-ASSEMBLYLOAD-EGRESS":     {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "NuGet install hook reflectively loads an assembly (Assembly.Load) AND contacts the network", Differentiator: "a benign init.ps1 only sets up project references; reflective load + network from an install hook is staged execution/exfil"},
	"JS-INSTALL-REMOTE-IMPORT":      {Intent: IntentMalicious, Tactic: "TA0002 Execution", Behavior: "npm install hook require()/imports from a remote https URL", Differentiator: "benign packages load registry dependencies via package.json, not a remote URL in an install hook"},
	"PY-SETUP-IMPORTLIB-EXEC":       {Intent: IntentObfuscation, Tactic: "TA0005 Defense Evasion", Behavior: "setup.py uses importlib/imp to load a module and immediately exec/compile/eval it", Differentiator: "benign setup.py imports pinned dependencies plainly; dynamic module load + exec at install time hides a staged payload"},
}

// defaultQualification is returned for signals without an explicit entry. It
// labels the signal dual-use (the conservative intent for an unrecognised
// pattern hit) so the advisory still carries an intent + a prompt to review.
var defaultQualification = Qualification{
	Intent:         IntentDualUse,
	Tactic:         "TA0002 Execution",
	Behavior:       "matched a malscan-engine detection pattern",
	Differentiator: "review the matched line: dual-use tools are malicious only in an auto-execution surface (install hook / PKGBUILD build()) compounded by another signal",
}

// Qualify returns the Qualification for a finding's signal id. The "IS-"
// install-script prefix is normalised so a rule has one qualification regardless
// of the surface it fired on. Unknown signals get the dual-use default so every
// finding carries an intent label.
func Qualify(f Finding) Qualification {
	if f.ID == "" {
		return defaultQualification
	}
	base := strings.TrimPrefix(f.ID, "IS-")
	if q, ok := qualRegistry[base]; ok {
		q.Signal = f.ID
		return q
	}
	// Substring fallbacks for the gtfobins/pattern families whose ids carry a
	// technique stem (G-PIPE-*, G-DOWNLOAD-*, P-INSTALL-*).
	for key, q := range qualRegistry {
		if strings.Contains(base, key) {
			q.Signal = f.ID
			return q
		}
	}
	d := defaultQualification
	d.Signal = f.ID
	return d
}

// IntentOf is a convenience returning just the Intent for a finding.
func IntentOf(f Finding) Intent { return Qualify(f).Intent }
