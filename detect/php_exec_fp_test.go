package detect

import "testing"

// PHP-SHELL-EXEC-VAR matched the TAIL of any identifier ending in "exec", because
// its pattern had no boundary guard before the alternation. curl_exec($ch) and
// $pdo->exec($sql) are ordinary PHP and both fired.
//
// Measured on production 2026-08-07: the rule appeared in 10,792 of packagist's
// 15,677 malware mints (69%), and mints whose only evidence was this rule pointed at
// lines like "$raw = curl_exec($ch);" and "$pdo->exec($sql);". A malware feed whose
// majority rule fires on the standard PHP cURL call cannot support a blocking
// decision, which is what packagist's business-goal gate failed on.

// Benign PHP that must NOT trip the rule.
const benignPHP = `<?php
class Client {
    public function fetch($url) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $raw = curl_exec($ch);
        curl_close($ch);
        return $raw;
    }
    public function store($sql) {
        $pdo = new PDO($this->dsn);
        return $pdo->exec($sql);
    }
    public function viaStatic($cmd) {
        return Runner::exec($cmd);
    }
}`

// Genuine OS command execution on a variable — the rule MUST still fire.
const maliciousPHP = `<?php
$cmd = $_GET['c'];
system($cmd);
`

func TestPHPShellExecVarIgnoresBenignExecSuffixes(t *testing.T) {
	f := Detect(&PackageContext{Name: "vendor/pkg", PkgbuildContent: benignPHP})
	if has(f, "PHP-SHELL-EXEC-VAR") {
		t.Errorf("PHP-SHELL-EXEC-VAR fired on curl_exec/$pdo->exec/Runner::exec; findings=%v", ids(f))
	}
}

func TestPHPShellExecVarStillCatchesRealExec(t *testing.T) {
	f := Detect(&PackageContext{Name: "vendor/pkg", PkgbuildContent: maliciousPHP})
	if !has(f, "PHP-SHELL-EXEC-VAR") {
		t.Errorf("PHP-SHELL-EXEC-VAR did not fire on system($cmd); the guard is too broad. findings=%v", ids(f))
	}
}

// Each dangerous sink on its own, so a future edit to the alternation cannot
// silently drop one, and each benign look-alike, so the guard cannot be narrowed
// back to the broken form.
func TestPHPShellExecVarPerSink(t *testing.T) {
	fire := map[string]string{
		"system":          "<?php system($cmd);",
		"exec":            "<?php exec($cmd);",
		"shell_exec":      "<?php shell_exec($cmd);",
		"passthru":        "<?php passthru($cmd);",
		"proc_open":       "<?php proc_open($cmd, $d, $p);",
		"popen":           "<?php popen($cmd, 'r');",
		"after semicolon": "<?php $x = 1; exec($cmd);",
	}
	for name, src := range fire {
		t.Run("fires/"+name, func(t *testing.T) {
			f := Detect(&PackageContext{Name: "vendor/pkg", PkgbuildContent: src})
			if !has(f, "PHP-SHELL-EXEC-VAR") {
				t.Errorf("did not fire on %q", src)
			}
		})
	}

	quiet := map[string]string{
		"curl_exec":   "<?php $raw = curl_exec($ch);",
		"method call": "<?php $pdo->exec($sql);",
		"static call": "<?php Runner::exec($cmd);",
		"variable fn": "<?php $exec($cmd);",
		"custom sink": "<?php my_exec($cmd);",
		"mysqli_ping": "<?php $db->real_exec($sql);",
	}
	for name, src := range quiet {
		t.Run("quiet/"+name, func(t *testing.T) {
			f := Detect(&PackageContext{Name: "vendor/pkg", PkgbuildContent: src})
			if has(f, "PHP-SHELL-EXEC-VAR") {
				t.Errorf("fired on benign %q", src)
			}
		})
	}
}

// PHP-ASSERT-VAR had the identical unanchored-tail flaw and carried 665 packagist
// mints on its own: $validator->assert($value) and Check::assert($x) are ordinary
// application and test code. PHPUnit's assertEquals/assertSame never matched either
// way, since a character follows "assert" before the paren.
func TestPHPAssertVarBoundary(t *testing.T) {
	quiet := map[string]string{
		"method call":    "<?php $validator->assert($value);",
		"static call":    "<?php Check::assert($x);",
		"custom suffix":  "<?php my_assert($x);",
		"variable fn":    "<?php $assert($x);",
		"phpunit equals": "<?php $this->assertEquals($a, $b);",
	}
	for name, src := range quiet {
		t.Run("quiet/"+name, func(t *testing.T) {
			f := Detect(&PackageContext{Name: "vendor/pkg", PkgbuildContent: src})
			if has(f, "PHP-ASSERT-VAR") {
				t.Errorf("PHP-ASSERT-VAR fired on benign %q", src)
			}
		})
	}

	loud := map[string]string{
		"bare call":       "<?php assert($code);",
		"after semicolon": "<?php $x = 1; assert($code);",
		"with space":      "<?php assert ($code);",
	}
	for name, src := range loud {
		t.Run("fires/"+name, func(t *testing.T) {
			f := Detect(&PackageContext{Name: "vendor/pkg", PkgbuildContent: src})
			if !has(f, "PHP-ASSERT-VAR") {
				t.Errorf("PHP-ASSERT-VAR did not fire on %q", src)
			}
		})
	}
}
