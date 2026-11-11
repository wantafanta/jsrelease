// Package parser extracts release entries from the official
// releases.jquery.com pages and release dates from uncompressed JavaScript
// file headers.
//
// The release pages are generated from the jquery/codeorigin.jquery.com
// repository. Every release is rendered as
//
//	jQuery Core 3.7.1: <a class='open-sri-modal' href='https://code.jquery.com/jquery-3.7.1.js' ...>uncompressed</a>, <a ...>minified</a>, ...
//	jQuery Core 4.0.0: <br>script: <a ... href='.../jquery-4.0.0.js'>uncompressed</a>, ... <br>module: <a ... href='.../jquery-4.0.0.module.js'>uncompressed</a>, ...
//	jQuery UI 1.14.2: <a ... href='https://code.jquery.com/ui/1.14.2/jquery-ui.js'>uncompressed</a>, ...
//	jQuery Mobile 1.4.5 - <a ... href='https://code.jquery.com/mobile/1.4.5/jquery.mobile-1.4.5.js'>uncompressed</a>, ...
//
// jQuery Migrate releases are listed on the Core page ("jQuery Migrate 3.4.1: ...").
// There is no separate Migrate page.
package jquery

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/wantafanta/jsrelease/internal/catalog"
)

// Page describes one official release page and the libraries it lists.
type Page struct {
	Name      string
	URL       string
	Libraries []catalog.Library
}

// Entry is one release found on a release page.
type Entry struct {
	Library catalog.Library
	// Version is the version exactly as the official release page shows it.
	Version string
	// FileVersion is the version embedded in the uncompressed file name; it
	// may be un-normalised (e.g. "1.2" for the page's "1.2.0").
	FileVersion string
	// URL is the absolute URL of the uncompressed JavaScript file.
	URL string
}

var labelToLibrary = map[string]catalog.Library{
	"core":    catalog.Core,
	"migrate": catalog.Migrate,
	"ui":      catalog.UI,
	"mobile":  catalog.Mobile,
}

// entryRe matches "<label> <version><sep>" followed by the first link labelled
// "uncompressed". The separator is ":" (Core, Migrate, UI) or "-" (Mobile);
// typographic dashes and <br>/"script:" fillers are tolerated.
var entryRe = regexp.MustCompile(`(?is)\bjQuery\s+(Core|Migrate|UI|Mobile)\s+(\d[^\s:<&]*)\s*` +
	`(?::|-|\x{2013}|&#8211;|&ndash;|&#x2013;)(?:\s|<br\s*/?>|script:)*` +
	`<a\b([^>]*)>\s*uncompressed\s*</a>`)

var (
	anchorRe = regexp.MustCompile(`(?is)<a\b([^>]*)>`)
	hrefRe   = regexp.MustCompile(`(?is)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
)

// Uncompressed file name patterns, mirroring the official generator. Minified,
// packed, slim and module builds contain an extra ".suffix" and never match.
var (
	coreFileRe    = regexp.MustCompile(`^/jquery-(\d+\.\d+(?:\.\d+)?[^./]*)\.js$`)
	migrateFileRe = regexp.MustCompile(`^/jquery-migrate-(\d+\.\d+(?:\.\d+)?[^./]*)\.js$`)
	uiFileRe      = regexp.MustCompile(`^/ui/([^/]+)/jquery-ui\.js$`)
	mobileFileRe  = regexp.MustCompile(`^/mobile/([^/]+)/jquery\.mobile-([^/]+)\.js$`)
)

// FileVersion reports whether the path of u is the uncompressed file of lib,
// and returns the version embedded in the file name.
func FileVersion(lib catalog.Library, u *url.URL) (string, bool) {
	p := u.EscapedPath()
	switch lib {
	case catalog.Core:
		if m := coreFileRe.FindStringSubmatch(p); m != nil {
			return m[1], true
		}
	case catalog.Migrate:
		if m := migrateFileRe.FindStringSubmatch(p); m != nil {
			return m[1], true
		}
	case catalog.UI:
		if m := uiFileRe.FindStringSubmatch(p); m != nil && startsWithDigit(m[1]) {
			return m[1], true
		}
	case catalog.Mobile:
		if m := mobileFileRe.FindStringSubmatch(p); m != nil && m[1] == m[2] && startsWithDigit(m[1]) {
			return m[1], true
		}
	}
	return "", false
}

func startsWithDigit(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

var rversion = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?-?(.*)$`)

// NormalizeVersion applies the same normalisation as the official page
// generator: "1.2" -> "1.2.0", "1.4rc1" -> "1.4.0-rc1", "1.0a4.1" -> "1.0.0-a4.1".
func NormalizeVersion(v string) string {
	m := rversion.FindStringSubmatch(v)
	if m == nil {
		return v
	}
	patch := m[3]
	if patch == "" {
		patch = "0"
	}
	out := m[1] + "." + m[2] + "." + patch
	if m[4] != "" {
		out += "-" + m[4]
	}
	return out
}

// StructureError reports that a release page no longer looks as expected.
type StructureError struct {
	Page     string
	Problems []string
}

func (e *StructureError) Error() string {
	return fmt.Sprintf("unexpected HTML structure on %s (the page layout may have changed): %s",
		e.Page, strings.Join(e.Problems, "; "))
}

// ParsePage extracts the releases of page.Libraries from the HTML of page.
// Links must point to one of allowedHosts. Any inconsistency is reported as a
// *StructureError rather than producing partial results.
func ParsePage(html []byte, page Page, allowedHosts []string) ([]Entry, error) {
	base, err := url.Parse(page.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid page URL %q: %w", page.URL, err)
	}
	wanted := map[catalog.Library]bool{}
	for _, l := range page.Libraries {
		wanted[l] = true
	}
	hosts := map[string]bool{}
	for _, h := range allowedHosts {
		hosts[strings.ToLower(h)] = true
	}
	serr := &StructureError{Page: page.URL}
	problem := func(format string, args ...any) {
		serr.Problems = append(serr.Problems, fmt.Sprintf(format, args...))
	}

	text := string(html)
	var entries []Entry
	listed := map[string]bool{} // URLs captured as the uncompressed file of an entry

	for _, m := range entryRe.FindAllStringSubmatch(text, -1) {
		lib := labelToLibrary[strings.ToLower(m[1])]
		if !wanted[lib] {
			continue
		}
		version := strings.TrimSpace(m[2])
		label := lib.DisplayName() + " " + version
		u, err := resolveHref(base, m[3])
		if err != nil {
			problem("%s: %v", label, err)
			continue
		}
		if !hosts[strings.ToLower(u.Hostname())] {
			problem("%s: uncompressed link %s is not on an allowed host (%s)", label, u, strings.Join(allowedHosts, ", "))
			continue
		}
		fv, ok := FileVersion(lib, u)
		if !ok {
			problem("%s: link labelled 'uncompressed' does not point to an uncompressed %s file: %s", label, lib.DisplayName(), u)
			continue
		}
		if version != fv && version != NormalizeVersion(fv) {
			problem("%s: version on page does not match file name version %q (%s)", label, fv, u)
			continue
		}
		listed[u.String()] = true
		entries = append(entries, Entry{Library: lib, Version: version, FileVersion: fv, URL: u.String()})
	}

	// Cross-check: every uncompressed file link of a wanted library anywhere on
	// the page must belong to a recognised release entry. Anything else means
	// the markup changed in a way the entry pattern no longer understands.
	for _, am := range anchorRe.FindAllStringSubmatch(text, -1) {
		u, err := resolveHref(base, am[1])
		if err != nil || !hosts[strings.ToLower(u.Hostname())] {
			continue
		}
		for lib := range wanted {
			if _, ok := FileVersion(lib, u); ok && !listed[u.String()] {
				problem("link to uncompressed %s file %s is not attached to a recognisable release entry", lib.DisplayName(), u)
			}
		}
	}

	entries = dedupe(entries)
	counts := map[catalog.Library]int{}
	for _, e := range entries {
		counts[e.Library]++
	}
	for _, l := range page.Libraries {
		if counts[l] == 0 {
			problem("no %s releases found", l.DisplayName())
		}
	}
	if len(serr.Problems) > 0 {
		return nil, serr
	}
	return entries, nil
}

// dedupe keeps one entry per library and version. The official page lists
// some versions twice because the generator normalises the version shown
// (e.g. both jquery-1.7.js and jquery-1.7.0.js are shown as "1.7.0"); the
// entry whose file name matches the displayed version exactly is preferred.
func dedupe(in []Entry) []Entry {
	index := map[string]int{}
	var out []Entry
	for _, e := range in {
		key := string(e.Library) + "@" + e.Version
		i, seen := index[key]
		if !seen {
			index[key] = len(out)
			out = append(out, e)
			continue
		}
		if out[i].FileVersion != out[i].Version && e.FileVersion == e.Version {
			out[i] = e
		}
	}
	return out
}

func resolveHref(base *url.URL, attrs string) (*url.URL, error) {
	m := hrefRe.FindStringSubmatch(attrs)
	if m == nil {
		return nil, errors.New("link without href")
	}
	raw := m[1] + m[2] + m[3]
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "&amp;", "&"))
	ref, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid href %q: %w", raw, err)
	}
	u := base.ResolveReference(ref)
	u.RawQuery, u.Fragment = "", ""
	return u, nil
}
