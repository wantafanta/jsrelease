package jquery

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/wantafanta/jsrelease/internal/catalog"
)

var allowed = []string{"code.jquery.com"}

var (
	corePage   = Page{Name: "core", URL: "https://releases.jquery.com/jquery/", Libraries: []catalog.Library{catalog.Core, catalog.Migrate}}
	uiPage     = Page{Name: "ui", URL: "https://releases.jquery.com/ui/", Libraries: []catalog.Library{catalog.UI}}
	mobilePage = Page{Name: "mobile", URL: "https://releases.jquery.com/mobile/", Libraries: []catalog.Library{catalog.Mobile}}
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseAll(t *testing.T) []Entry {
	t.Helper()
	var all []Entry
	for _, c := range []struct {
		file string
		page Page
	}{{"releases-jquery.html", corePage}, {"releases-ui.html", uiPage}, {"releases-mobile.html", mobilePage}} {
		es, err := ParsePage(readTestdata(t, c.file), c.page, allowed)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		all = append(all, es...)
	}
	return all
}

// TestParsePagesMatchIndependentList compares the parser's output for the
// three official pages with the list derived independently from the CDN
// repository's file tree.
func TestParsePagesMatchIndependentList(t *testing.T) {
	var got []string
	for _, e := range parseAll(t) {
		got = append(got, string(e.Library)+" "+e.Version+" "+e.URL)
	}
	var want []string
	f, err := os.Open(filepath.Join("testdata", "expected-entries.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			want = append(want, line)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseCorePageDetails(t *testing.T) {
	es, err := ParsePage(readTestdata(t, "releases-jquery.html"), corePage, allowed)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[catalog.Library]int{}
	byKey := map[string]Entry{}
	for _, e := range es {
		counts[e.Library]++
		byKey[string(e.Library)+"@"+e.Version] = e
		for _, bad := range []string{".min.", ".slim.", ".module.", ".pack.", "git", "/migrate/"} {
			if strings.Contains(e.URL, bad) {
				t.Errorf("%s %s: URL %s is not an uncompressed release file", e.Library, e.Version, e.URL)
			}
		}
	}
	if counts[catalog.Core] != 87 || counts[catalog.Migrate] != 22 || len(counts) != 2 {
		t.Fatalf("counts = %v, want core 87, migrate 22", counts)
	}
	checks := map[string]string{
		"core@4.0.0":    "https://code.jquery.com/jquery-4.0.0.js", // not the .module.js "uncompressed" link
		"core@3.7.1":    "https://code.jquery.com/jquery-3.7.1.js",
		"core@1.7.0":    "https://code.jquery.com/jquery-1.7.0.js", // listed twice (1.7 and 1.7.0)
		"core@1.2.0":    "https://code.jquery.com/jquery-1.2.js",   // page shows the normalised version
		"migrate@3.4.1": "https://code.jquery.com/jquery-migrate-3.4.1.js",
		"migrate@4.0.2": "https://code.jquery.com/jquery-migrate-4.0.2.js",
	}
	for k, url := range checks {
		if byKey[k].URL != url {
			t.Errorf("%s: URL = %q, want %q", k, byKey[k].URL, url)
		}
	}
}

func TestParseUIAndMobileDetails(t *testing.T) {
	ui, err := ParsePage(readTestdata(t, "releases-ui.html"), uiPage, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if len(ui) != 66 {
		t.Fatalf("UI releases = %d, want 66", len(ui))
	}
	mob, err := ParsePage(readTestdata(t, "releases-mobile.html"), mobilePage, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if len(mob) != 42 {
		t.Fatalf("Mobile releases = %d, want 42", len(mob))
	}
	find := func(es []Entry, v string) Entry {
		for _, e := range es {
			if e.Version == v {
				return e
			}
		}
		t.Fatalf("version %s not found", v)
		return Entry{}
	}
	if e := find(ui, "1.14.2"); e.URL != "https://code.jquery.com/ui/1.14.2/jquery-ui.js" {
		t.Errorf("UI 1.14.2 URL = %s", e.URL)
	}
	if e := find(ui, "1.13.0-rc.2"); e.FileVersion != "1.13.0-rc.2" {
		t.Errorf("UI pre-release not parsed: %+v", e)
	}
	if e := find(mob, "1.0.0-a4.1"); e.URL != "https://code.jquery.com/mobile/1.0a4.1/jquery.mobile-1.0a4.1.js" {
		t.Errorf("Mobile 1.0.0-a4.1 URL = %s", e.URL)
	}
}

// TestParseToleratesRenderingVariants covers markup changes a CMS could
// introduce: double quotes, protocol-relative links, <br /> and en dashes.
func TestParseToleratesRenderingVariants(t *testing.T) {
	html := `<ul>
<li>jQuery Core 3.7.1: <br /><a class="open-sri-modal" href="//code.jquery.com/jquery-3.7.1.js">uncompressed</a>, <a href="//code.jquery.com/jquery-3.7.1.min.js">minified</a></li>
<li>jQuery Migrate 3.4.1 &#8211; <a href='https://code.jquery.com/jquery-migrate-3.4.1.js?v=1'>uncompressed</a></li>
</ul>`
	es, err := ParsePage([]byte(html), corePage, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 || es[0].URL != "https://code.jquery.com/jquery-3.7.1.js" || es[1].URL != "https://code.jquery.com/jquery-migrate-3.4.1.js" {
		t.Fatalf("unexpected entries: %+v", es)
	}
}

func TestParseReportsStructureChanges(t *testing.T) {
	cases := map[string]string{
		"no releases":     `<html><body><p>Maintenance</p></body></html>`,
		"migrate missing": `<li>jQuery Core 3.7.1: <a href='https://code.jquery.com/jquery-3.7.1.js'>uncompressed</a></li>`,
		"uncompressed points to minified": `<li>jQuery Core 3.7.1: <a href='https://code.jquery.com/jquery-3.7.1.min.js'>uncompressed</a></li>
<li>jQuery Migrate 3.4.1: <a href='https://code.jquery.com/jquery-migrate-3.4.1.js'>uncompressed</a></li>`,
		"version mismatch": `<li>jQuery Core 3.7.0: <a href='https://code.jquery.com/jquery-3.7.1.js'>uncompressed</a></li>
<li>jQuery Migrate 3.4.1: <a href='https://code.jquery.com/jquery-migrate-3.4.1.js'>uncompressed</a></li>`,
		"foreign host": `<li>jQuery Core 3.7.1: <a href='https://evil.example/jquery-3.7.1.js'>uncompressed</a></li>
<li>jQuery Migrate 3.4.1: <a href='https://code.jquery.com/jquery-migrate-3.4.1.js'>uncompressed</a></li>`,
		"unrecognised entry layout": `<li>jQuery Core 3.7.1: <a href='https://code.jquery.com/jquery-3.7.1.js'>uncompressed</a></li>
<li>jQuery Migrate 3.4.1: <a href='https://code.jquery.com/jquery-migrate-3.4.1.js'>uncompressed</a></li>
<tr><td>3.7.0</td><td><a href='https://code.jquery.com/jquery-3.7.0.js'>download</a></td></tr>`,
	}
	for name, html := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParsePage([]byte(html), corePage, allowed)
			var se *StructureError
			if !errors.As(err, &se) {
				t.Fatalf("expected *StructureError, got %v", err)
			}
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	for in, want := range map[string]string{
		"1.2": "1.2.0", "1.7": "1.7.0", "3.7.1": "3.7.1", "1.0a4.1": "1.0.0-a4.1",
		"1.4rc1": "1.4.0-rc1", "1.5.0-rc1": "1.5.0-rc1", "1.11.0-beta.1": "1.11.0-beta.1",
	} {
		if got := NormalizeVersion(in); got != want {
			t.Errorf("NormalizeVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDedupePrefersExactFileName: whichever order the page lists them in, the
// entry whose file name equals the displayed version wins.
func TestDedupePrefersExactFileName(t *testing.T) {
	html := `<li>jQuery Core 1.7.0: <a href='https://code.jquery.com/jquery-1.7.js'>uncompressed</a></li>
<li>jQuery Core 1.7.0: <a href='https://code.jquery.com/jquery-1.7.0.js'>uncompressed</a></li>
<li>jQuery Migrate 3.4.1: <a href='https://code.jquery.com/jquery-migrate-3.4.1.js'>uncompressed</a></li>`
	es, err := ParsePage([]byte(html), corePage, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 || es[0].URL != "https://code.jquery.com/jquery-1.7.0.js" {
		t.Fatalf("unexpected entries: %+v", es)
	}
}
