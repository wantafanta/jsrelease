package runner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/wantafanta/jsrelease/internal/vuln"
)

func TestCheck(t *testing.T) {
	path, _ := updatedDB(t)
	code, out, stderr := execText(t, nil, "-data", path, "-library", "core", "-check", "3.4.1")
	want := "" +
		"Library  Version  Release Date  Support        Latest  Latest Release Date\n" +
		"jQuery   3.4.1    01/05/2019    Security only  4.0.0   18/01/2026\n" +
		"\n" +
		"CVE / Advisory                        Severity  CVSS  Summary\n" +
		"CVE-2020-11022                        Medium    6.9   Potential XSS vulnerability in jQuery\n" +
		"CVE-2020-11023 (also CVE-2020-23064)  Medium    6.9   Potential XSS vulnerability in jQuery\n"
	if code != 0 || out != want {
		t.Fatalf("code %d\ngot:\n%s\nwant:\n%s\nstderr:%s", code, out, want, stderr)
	}
	if !strings.Contains(stderr, "Checked jQuery 3.4.1 and 10 later release(s) up to 4.0.0: 2 advisories") {
		t.Errorf("info missing: %s", stderr)
	}

	// Option B: 1.12.2 is not itself affected by CVE-2015-9251, but later
	// releases up to the latest are, so it is listed.
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-check", "1.12.2", "-s")
	if !strings.Contains(out, "CVE-2015-9251") || strings.Contains(out, "CVE-2011-4969") {
		t.Errorf("1.12.2 check:\n%s", out)
	}

	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-check", "4.0.0")
	if !strings.HasSuffix(out, "\nNo known advisories affect jQuery 4.0.0.\n") {
		t.Errorf("no advisories:\n%s", out)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "ui", "-check", "1.13.2", "-s")
	if out != "jQuery UI  1.13.2   14/07/2022    Unsupported\u2020  1.14.2  28/01/2026\n" {
		t.Errorf("silent, none:\n%q", out)
	}

	// Unfixed advisory affecting the latest release is warned about.
	code, out, stderr = execText(t, nil, "-data", path, "-library", "mobile", "-check", "1.4.5", "-cols", "advisory,severity,cvss,range,fixed")
	if code != 0 || !strings.Contains(out, "GHSA-fj93-7wm4-8x2g  High      -     >= 0              none") ||
		!strings.Contains(stderr, "[WRN] GHSA-fj93-7wm4-8x2g also affects the latest release jQuery Mobile 1.4.5 (it has no fixed version)") {
		t.Errorf("mobile:\n%s\n%s", out, stderr)
	}

	// JSON and Markdown forms.
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-check", "3.4.1", "-json", "-s")
	var res vuln.CheckResult
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Latest != "4.0.0" || len(res.Advisories) != 2 || len(res.Checked) != 11 {
		t.Errorf("json: %v %+v", err, res)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-check", "3.4.1", "-md", "-s")
	wantMD := "" +
		"| Library | Version | Release Date | Support       | Latest | Latest Release Date |\n" +
		"|---------|---------|--------------|---------------|--------|---------------------|\n" +
		"| jQuery  | 3.4.1   | 01/05/2019   | Security only | 4.0.0  | 18/01/2026          |\n" +
		"\n" +
		"| CVE / Advisory                       | Severity | CVSS | Summary                               |\n" +
		"|--------------------------------------|----------|------|---------------------------------------|\n" +
		"| CVE-2020-11022                       | Medium   | 6.9  | Potential XSS vulnerability in jQuery |\n" +
		"| CVE-2020-11023 (also CVE-2020-23064) | Medium   | 6.9  | Potential XSS vulnerability in jQuery |\n"
	if out != wantMD {
		t.Errorf("markdown check:\n%s\nwant:\n%s", out, wantMD)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-check", "1.12.2", "-md", "-s", "-cols", "advisory,range")
	if !strings.Contains(out, "| < 1.12.2 \\| >= 1.12.3, < 3.0.0 |") {
		t.Errorf("pipe not escaped:\n%s", out)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-check", "4.0.0", "-md")
	if !strings.HasSuffix(out, "|\n\nNo known advisories affect jQuery 4.0.0.\n") {
		t.Errorf("markdown, none:\n%s", out)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-check", "4.0.0", "-md", "-s")
	if strings.Contains(out, "No known") || strings.Count(out, "\n") != 3 {
		t.Errorf("markdown silent, none:\n%s", out)
	}

	// CVSS from NVD (CVSS v2, labelled) and in JSON output.
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-check", "1.2.0", "-s", "-cols", "advisory,severity,cvss,range")
	if !strings.Contains(out, "CVE-2011-4969                         Medium    4.3 (v2.0)  < 1.6.3") {
		t.Errorf("NVD score:\n%s", out)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-json", "-s")
	if !strings.Contains(out, `"cvss": {
          "version": "3.1",
          "score": 6.9,`) {
		t.Errorf("cvss missing from -cve -json")
	}

	// Errors.
	if code, _, stderr := execText(t, nil, "-data", path, "-check", "3.4.1"); code != 2 || !strings.Contains(stderr, "single library") {
		t.Errorf("no library: %d %s", code, stderr)
	}
	if code, _, stderr := execText(t, nil, "-data", path, "-library", "core", "-check", "3.4.9"); code != 1 || !strings.Contains(stderr, "not a known release") {
		t.Errorf("unknown version: %d %s", code, stderr)
	}
	removeVulns(t, path)
	if code, _, stderr := execText(t, nil, "-data", path, "-library", "core", "-check", "3.4.1"); code != 1 || !strings.Contains(stderr, "no vulnerability data in") {
		t.Errorf("missing file: %d %s", code, stderr)
	}
}

func TestSupportStatus(t *testing.T) {
	path, _ := updatedDB(t)
	cases := []struct{ lib, v, warn string }{
		{"core", "3.4.1", "[WRN] jQuery 3.4.1 (Security only): its line receives security fixes only; the newest release in its line is 3.7.1, the latest is 4.0.0"},
		{"bootstrap", "3.4.1", "[WRN] Bootstrap 3.4.1 (Unsupported since 24/07/2019): the latest is 5.3.8"},
		{"ui", "1.12.1", "[WRN] jQuery UI 1.12.1 (Unsupported since 07/10/2021; inferred: the project states no support policy for it): the latest is 1.14.2"},
		{"prototype", "1.7.3", "[WRN] Prototype 1.7.3 (Unsupported; inferred: the project states no support policy for it)"},
		{"moment", "2.31.0", "[WRN] Moment.js 2.31.0 (Security only): its line receives security fixes only"},
	}
	for _, c := range cases {
		_, _, stderr := execText(t, nil, "-data", path, "-library", c.lib, "-check", c.v, "-cols", "advisory")
		if !strings.Contains(stderr, c.warn+"\n") {
			t.Errorf("%s %s: missing %q\n%s", c.lib, c.v, c.warn, stderr)
		}
	}
	if _, _, stderr := execText(t, nil, "-data", path, "-library", "core", "-check", "4.0.0"); strings.Contains(stderr, "Supported") {
		t.Error("no warning expected for a supported version")
	}
	// JSON: lowercase status, basis and source, in -check and listings.
	_, out, _ := execText(t, nil, "-data", path, "-library", "core", "-check", "3.4.1", "-json", "-s")
	if !strings.Contains(out, `"status": "security-only"`) || !strings.Contains(out, `"basis": "official"`) || !strings.Contains(out, `"source": "https://jquery.com/support/"`) {
		t.Errorf("check JSON:\n%s", out)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "mobile", "-json", "-s")
	if !strings.Contains(out, `"status": "unsupported"`) || !strings.Contains(out, `"since": "07/10/2021"`) {
		t.Error("list JSON support")
	}
	// -cols support, alone.
	_, out, _ = execText(t, nil, "-data", path, "-library", "bootstrap", "-cols", "version,support", "-s")
	if !strings.HasPrefix(out, "6.0.0-alpha.1    Unsupported\u2020\n") || !strings.Contains(out, "\n5.3.8            Supported\n") {
		t.Errorf("-cols support:\n%s", out[:200])
	}
}

func TestPrototypeLatestWarning(t *testing.T) {
	path, _ := updatedDB(t)
	_, _, stderr := execText(t, nil, "-data", path, "-library", "prototype", "-check", "1.7.3")
	if !strings.Contains(stderr, "[WRN] CVE-2020-27511 also affects the latest release Prototype 1.7.3 (NVD gives no fixed version)\n") {
		t.Errorf("warning:\n%s", stderr)
	}
}
