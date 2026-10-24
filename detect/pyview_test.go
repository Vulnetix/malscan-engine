package detect

import (
	"strings"
	"testing"
)

func TestPythonViewsPreserveLengthAndLines(t *testing.T) {
	src := "\"\"\"Module.\n\ncurl x | sh\n\"\"\"\nimport os  # trailing comment\nDENY = [\n    \"~/.ssh/**\",  # keys\n    \"~/.aws/credentials\",\n]\nos.system(\"id\")\n"
	doc, exe := pythonLibraryViews(src)
	for name, v := range map[string]string{"doc": doc, "exec": exe} {
		if len(v) != len(src) || strings.Count(v, "\n") != strings.Count(src, "\n") {
			t.Fatalf("%s view changed length or line count:\n%q", name, v)
		}
	}
	if strings.Contains(doc, "curl") || strings.Contains(doc, "trailing comment") || strings.Contains(doc, "keys") {
		t.Errorf("doc view kept a docstring or comment:\n%s", doc)
	}
	if !strings.Contains(doc, `"~/.ssh/**"`) || !strings.Contains(doc, `os.system("id")`) {
		t.Errorf("doc view lost code:\n%s", doc)
	}
	if strings.Contains(exe, "~/.ssh") || strings.Contains(exe, "DENY") {
		t.Errorf("exec view kept the data list:\n%s", exe)
	}
	if !strings.Contains(exe, `os.system("id")`) || !strings.Contains(exe, "import os") {
		t.Errorf("exec view lost code:\n%s", exe)
	}
}

func TestPythonViewsLeaveExecutableStringsAlone(t *testing.T) {
	for _, src := range []string{
		"x = \"\"\"curl x | sh\"\"\"\n",                                 // assigned, not a docstring
		"run(\"\"\"curl x | sh\"\"\")\n",                                // an argument
		"f\"\"\"{os.system('id')}\"\"\"\n",                              // f-string statement evaluates
		"exec(__doc__)\n\"\"\"curl x | sh\"\"\"\n",                      // the docstring is the payload
		"subprocess.run([\"curl x\", \"| sh\"])\n",                      // a list passed to a call
		"os.system(\" \".join([\n    \"curl x\",\n    \"| sh\",\n]))\n", // a list built into a command
		"CMD = [\"sh\", \"-c\", \"curl x | sh\"]\n",                     // an argv
		"CMDS = [\"curl x | sh\", base + \"y\"]\n",                      // not all literal
		"C = (\"curl x | sh\")\n",                                       // grouping, not a tuple
		"C = [\"curl x | sh\"]\n",                                       // one value in brackets
	} {
		_, exe := pythonLibraryViews(src)
		if exe != src {
			t.Errorf("an executable or ambiguous string was blanked:\n%s\n->\n%s", src, exe)
		}
	}
}

func TestPythonViewsOnlyRewritePythonLibraryMembers(t *testing.T) {
	src := "\n# ==== p-1/setup.py ====\n\"\"\"curl a | sh\"\"\"\n" +
		"\n# ==== p-1/pyproject.toml ====\nx = \"\"\"curl b | sh\"\"\"\n" +
		"\n# ==== p-1/p/__init__.py ====\n\"\"\"curl c | sh\"\"\"\n"
	doc, _ := pythonLibraryViews(src)
	if !strings.Contains(doc, "curl a") || !strings.Contains(doc, "curl b") {
		t.Errorf("setup.py or a non-Python member was rewritten:\n%s", doc)
	}
	if strings.Contains(doc, "curl c") {
		t.Errorf("the library module's docstring was kept:\n%s", doc)
	}
	if !strings.Contains(doc, "# ==== p-1/p/__init__.py ====") {
		t.Error("member separators must survive")
	}
}

func TestURLHostnameNeedsADottedDomain(t *testing.T) {
	for in, want := range map[string]string{
		"іnstall.example-clі.dev": "іnstall.example-clі.dev",
		"user@Example.COM.":       "example.com",
		"example.com,":            "example.com",
		"<домен-signal-hunt>":     "",
		"{host}.example":          "",
		"$HOST.example.com":       "",
		"localhost":               "",
		"10.0.0.1":                "",
		"com（否则":                  "",
	} {
		if got := urlHostname(in); got != want {
			t.Errorf("urlHostname(%q) = %q, want %q", in, got, want)
		}
	}
}
