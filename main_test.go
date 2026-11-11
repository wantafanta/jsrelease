package main

import (
	"testing"

	"github.com/wantafanta/jsrelease/internal/datafile"
)

func TestBuildVersion(t *testing.T) {
	version = "v2.0.1"
	if v := buildVersion(); v != "2.0.1" {
		t.Errorf("release build: %q", v)
	}
	version = ""
	if v := buildVersion(); v != "dev" { // go test builds have no module version
		t.Errorf("source build: %q", v)
	}
}

// TestBundledData: the data built into the binary is valid and complete.
func TestBundledData(t *testing.T) {
	db, err := datafile.ParseReleases(bundled, "bundled data")
	if err != nil || len(db.Releases) < 500 {
		t.Fatalf("bundled releases: %v", err)
	}
	vdb, err := datafile.ParseVulns(bundled, "bundled data")
	if err != nil || len(vdb.Advisories) < 30 {
		t.Fatalf("bundled vulnerabilities: %v", err)
	}
}
