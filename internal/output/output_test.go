package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wantafanta/jsrelease/internal/catalog"
)

var sample = []catalog.Release{
	{Library: catalog.Core, Name: "jQuery", Version: "3.7.1", ReleaseDate: "28/08/2023", SourceURL: "u1"},
	{Library: catalog.Migrate, Name: "jQuery Migrate", Version: "3.4.1", ReleaseDate: "23/02/2023", SourceURL: "u2"},
	{Library: catalog.UI, Name: "jQuery UI", Version: "1.8.18", SourceURL: "u3", DateNote: "no date"},
}

func TestWriteTable(t *testing.T) {
	var b bytes.Buffer
	if err := WriteTable(&b, sample, true); err != nil {
		t.Fatal(err)
	}
	// Support is worked out from these three releases alone: jQuery 3 is the
	// latest jQuery major here; Migrate 3 follows it (inferred); 1.8 is the
	// only (so latest) jQuery UI line here (inferred).
	want := "" +
		"Library         Version          Release Date  Support\n" +
		"jQuery          3.7.1            28/08/2023    Supported\n" +
		"jQuery Migrate  3.4.1            23/02/2023    Supported\u2020\n" +
		"jQuery UI       1.8.18           N/A           Supported\u2020\n" +
		"\n" + InferredFootnote + "\n"
	if b.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestWriteTableSilentAndWideVersions(t *testing.T) {
	var b bytes.Buffer
	rs := []catalog.Release{{Library: catalog.Mobile, Name: "jQuery Mobile", Version: "1.0.0-a4.1-extra-long", ReleaseDate: "01/01/2011"}}
	if err := WriteTable(&b, rs, false); err != nil {
		t.Fatal(err)
	}
	// A pre-release: unsupported (inferred). No footnote without a heading.
	if want := "jQuery Mobile   1.0.0-a4.1-extra-long  01/01/2011    Unsupported\u2020\n"; b.String() != want {
		t.Fatalf("got %q, want %q", b.String(), want)
	}
}

func TestWriteJSON(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJSON(&b, sample); err != nil {
		t.Fatal(err)
	}
	var got []catalog.Release
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, b.String())
	}
	if len(got) != 3 || got[0] != sample[0] || got[2].DateNote == "" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	b.Reset()
	if err := WriteJSON(&b, nil); err != nil || b.String() != "[]\n" {
		t.Fatalf("empty: %q %v", b.String(), err)
	}
}

func TestWriteMarkdown(t *testing.T) {
	var b bytes.Buffer
	if err := WriteMarkdown(&b, sample, nil); err != nil {
		t.Fatal(err)
	}
	want := "" +
		"| Library        | Version | Release Date | Support    |\n" +
		"|----------------|---------|--------------|------------|\n" +
		"| jQuery         | 3.7.1   | 28/08/2023   | Supported  |\n" +
		"| jQuery Migrate | 3.4.1   | 23/02/2023   | Supported\u2020 |\n" +
		"| jQuery UI      | 1.8.18  | N/A          | Supported\u2020 |\n" +
		"\n" + InferredFootnote + "\n"
	if b.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestMarkdownEscapingAndAlignment(t *testing.T) {
	tb := Table{Headers: []string{"A", "RANGE"}, Rows: [][]string{{"x", "< 1.12.2 | >= 1.12.3, < 3.0.0"}, {"yy", "ünïcode\nline"}}}
	var b bytes.Buffer
	if err := tb.Markdown(&b); err != nil {
		t.Fatal(err)
	}
	want := "" +
		"| A   | RANGE                          |\n" +
		"|-----|--------------------------------|\n" +
		"| x   | < 1.12.2 \\| >= 1.12.3, < 3.0.0 |\n" +
		"| yy  | ünïcode line                   |\n"
	if b.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestParseColumnsAndDates(t *testing.T) {
	got, err := ParseColumns(" CVSS ,link,advisory", AdvisoryColumnNames(), "x")
	if err != nil || strings.Join(got, ",") != "cvss,link,advisory" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", "cvss,", "cvss,cvss", "nope"} {
		if _, err := ParseColumns(bad, AdvisoryColumnNames(), "x"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if ukDate("2022-07-18") != "18/07/2022" || ukDate("") != "-" {
		t.Error("ukDate")
	}
	// Default columns reproduce the original tables exactly.
	if strings.Join(DefaultReleaseColumns(false), ",") != "library,version,date,support" ||
		strings.Join(DefaultAdvisoryColumns, ",") != "advisory,severity,cvss,summary" {
		t.Error("defaults changed")
	}
}
