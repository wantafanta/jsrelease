package datafile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/vuln"
)

func TestSectionsAreIndependent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", DefaultName)
	if _, err := ReadReleases(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	rel := catalog.New()
	rel.Releases = []catalog.Release{{Library: catalog.Core, Name: "jQuery", Version: "3.7.1", ReleaseDate: "28/08/2023", SourceURL: "u"}}
	if err := SaveReleases(p, rel); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVulns(p); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("no vulnerability section yet should look like a missing file: %v", err)
	}
	if err := SaveVulns(p, &vuln.Database{}); err != nil {
		t.Fatal(err)
	}
	// Saving one section keeps the other.
	rel.Releases[0].Version = "3.7.0"
	if err := SaveReleases(p, rel); err != nil {
		t.Fatal(err)
	}
	if v, err := ReadVulns(p); err != nil || v == nil {
		t.Fatalf("vulnerability section lost: %v", err)
	}
	if r, err := ReadReleases(p); err != nil || r.Releases[0].Version != "3.7.0" {
		t.Fatalf("releases: %v", err)
	}
	// Invalid data is refused; a corrupt file is replaced.
	bad := catalog.New()
	bad.Releases = []catalog.Release{{Library: catalog.Core}}
	if err := SaveReleases(p, bad); err == nil {
		t.Error("invalid database saved")
	}
	os.WriteFile(p, []byte("{not json"), 0o644)
	if err := SaveReleases(p, rel); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); !strings.HasPrefix(string(b), "{\n  \"releases\": {") {
		t.Errorf("layout:\n%s", b[:60])
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Errorf("temporary files left: %v", entries)
	}
}
