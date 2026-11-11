// Package datafile reads and writes jsrelease's data file, jsrelease.json,
// which holds two sections: the release database and the vulnerability
// database. Each section is read and saved on its own, so one can be updated
// while the other is kept as it is.
package datafile

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/vuln"
)

// DefaultName is the data file's name.
const DefaultName = "jsrelease.json"

type file struct {
	Releases        json.RawMessage `json:"releases,omitempty"`
	Vulnerabilities json.RawMessage `json:"vulnerabilities,omitempty"`
}

func read(path string) (file, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return file{}, err
	}
	return parse(data, path)
}

func parse(data []byte, name string) (file, error) {
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return file{}, fmt.Errorf("parse %s: %w", name, err)
	}
	return f, nil
}

// missing reports an absent section like an absent file, so callers can
// fall back (e.g. to the bundled data) the same way.
func missing(name, section string) error {
	return fmt.Errorf("%s has no %s yet: %w", name, section, fs.ErrNotExist)
}

// ReadReleases reads the release section of the file at path.
func ReadReleases(path string) (*catalog.Database, error) {
	f, err := read(path)
	if err != nil {
		return nil, err
	}
	return releasesOf(f, path)
}

// ReadVulns reads the vulnerability section of the file at path.
func ReadVulns(path string) (*vuln.Database, error) {
	f, err := read(path)
	if err != nil {
		return nil, err
	}
	return vulnsOf(f, path)
}

// ParseReleases reads the release section from data (e.g. bundled data).
func ParseReleases(data []byte, name string) (*catalog.Database, error) {
	f, err := parse(data, name)
	if err != nil {
		return nil, err
	}
	return releasesOf(f, name)
}

// ParseVulns reads the vulnerability section from data.
func ParseVulns(data []byte, name string) (*vuln.Database, error) {
	f, err := parse(data, name)
	if err != nil {
		return nil, err
	}
	return vulnsOf(f, name)
}

func releasesOf(f file, name string) (*catalog.Database, error) {
	if len(f.Releases) == 0 {
		return nil, missing(name, "releases")
	}
	return catalog.Parse(f.Releases, name)
}

func vulnsOf(f file, name string) (*vuln.Database, error) {
	if len(f.Vulnerabilities) == 0 {
		return nil, missing(name, "vulnerability data")
	}
	return vuln.Parse(f.Vulnerabilities, name)
}

// SaveReleases replaces the release section, keeping the other section.
func SaveReleases(path string, db *catalog.Database) error {
	if err := db.Validate(); err != nil {
		return fmt.Errorf("refusing to save an invalid database: %w", err)
	}
	return save(path, func(f *file) error {
		raw, err := json.Marshal(db)
		f.Releases = raw
		return err
	})
}

// SaveVulns replaces the vulnerability section, keeping the other section.
func SaveVulns(path string, db *vuln.Database) error {
	if err := db.Validate(); err != nil {
		return fmt.Errorf("refusing to save an invalid vulnerability database: %w", err)
	}
	return save(path, func(f *file) error {
		raw, err := json.Marshal(db)
		f.Vulnerabilities = raw
		return err
	})
}

// save rewrites the file atomically: a temporary file in the same folder,
// flushed to disk and renamed over the old one. An unreadable existing file
// is replaced.
func save(path string, change func(*file) error) (err error) {
	f, rerr := read(path)
	if rerr != nil {
		f = file{}
	}
	if err := change(&f); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".jsrelease-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(append(data, '\n')); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Combine builds a data file from separate release and vulnerability JSON.
func Combine(releases, vulnerabilities []byte) ([]byte, error) {
	data, err := json.MarshalIndent(file{Releases: releases, Vulnerabilities: vulnerabilities}, "", "  ")
	return append(data, '\n'), err
}
