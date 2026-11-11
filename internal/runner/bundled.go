package runner

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/datafile"
	"github.com/wantafanta/jsrelease/internal/vuln"
)

// Bundled holds the release data built into the binary (set by package
// main). It is used when no data file exists yet, so an installed jsrelease
// works straight away; -update then saves to the data folder.
var Bundled []byte

const bundledName = "the bundled data"

// readReleases loads the release database at path, or the bundled data if
// there is no file yet. It also says where the data came from.
func readReleases(path string) (*catalog.Database, string, error) {
	db, err := datafile.ReadReleases(path)
	if errors.Is(err, fs.ErrNotExist) && len(Bundled) > 0 {
		db, err = datafile.ParseReleases(Bundled, bundledName)
		return db, bundledName, err
	}
	return db, path, err
}

// readVulns is readReleases for the vulnerability database.
func readVulns(path string) (*vuln.Database, string, error) {
	db, err := datafile.ReadVulns(path)
	if errors.Is(err, fs.ErrNotExist) && len(Bundled) > 0 {
		db, err = datafile.ParseVulns(Bundled, bundledName)
		return db, bundledName, err
	}
	return db, path, err
}

// userDataDir is the per-user data folder: $XDG_DATA_HOME/jsrelease or
// ~/.local/share/jsrelease on Linux, ~/Library/Application Support/jsrelease
// on macOS, %LocalAppData%\jsrelease on Windows.
func userDataDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LocalAppData"); d != "" {
			return filepath.Join(d, "jsrelease"), nil
		}
	case "darwin":
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, "Library", "Application Support", "jsrelease"), nil
		}
	default:
		if d := os.Getenv("XDG_DATA_HOME"); d != "" {
			return filepath.Join(d, "jsrelease"), nil
		}
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, ".local", "share", "jsrelease"), nil
		}
	}
	return "", errors.New("cannot find your user data folder (use -data)")
}
