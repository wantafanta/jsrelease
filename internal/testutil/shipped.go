package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wantafanta/jsrelease/internal/catalog"
)

// ShippedFile is the path of the data file shipped in the repository.
func ShippedFile() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "jsrelease.json")
}

// ShippedReleases returns the releases in the shipped data file.
func ShippedReleases(t testing.TB) []catalog.Release {
	t.Helper()
	data, err := os.ReadFile(ShippedFile())
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Releases json.RawMessage `json:"releases"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	db, err := catalog.Parse(f.Releases, "shipped data")
	if err != nil {
		t.Fatal(err)
	}
	return db.Releases
}
