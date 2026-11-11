// Package config reads and writes jsrelease's config file, which holds the
// optional GitHub token and NVD API key. The file uses a simple subset of
// YAML ("key: value" lines and # comments), read without extra dependencies.
// Environment variables take priority over the file.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Keys stored in the file, and the environment variables that override them.
const (
	KeyGitHub = "github_token"
	KeyNVD    = "nvd_api_key"
	EnvGitHub = "GITHUB_TOKEN"
	EnvNVD    = "NVD_API_KEY"
)

var known = []string{KeyGitHub, KeyNVD}

// DefaultPath is the per-user config file, e.g. ~/.config/jsrelease/config.yaml
// on Linux, ~/Library/Application Support/jsrelease/config.yaml on macOS and
// %AppData%\jsrelease\config.yaml on Windows.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot find your user config folder: %w (use -config)", err)
	}
	return filepath.Join(dir, "jsrelease", "config.yaml"), nil
}

// Load reads the file at path. A missing file gives an empty map; the caller
// decides whether that matters (see errors.Is(err, fs.ErrNotExist) from Read).
func Load(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, path)
}

// Parse reads "key: value" lines; values may be quoted. Unknown keys and
// malformed lines are errors naming the line.
func Parse(r io.Reader, name string) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if !ok || key == "" {
			return nil, fmt.Errorf("%s line %d: expected \"key: value\"", name, n)
		}
		if !isKnown(key) {
			return nil, fmt.Errorf("%s line %d: unknown key %q (known: %s)", name, n, key, strings.Join(known, ", "))
		}
		switch {
		case strings.HasPrefix(val, `"`):
			u, err := strconv.Unquote(val)
			if err != nil {
				return nil, fmt.Errorf("%s line %d: badly quoted value", name, n)
			}
			val = u
		case strings.HasPrefix(val, "'"):
			if len(val) < 2 || !strings.HasSuffix(val, "'") {
				return nil, fmt.Errorf("%s line %d: badly quoted value", name, n)
			}
			val = strings.ReplaceAll(val[1:len(val)-1], "''", "'")
		default:
			if i := strings.Index(val, " #"); i >= 0 { // trailing comment
				val = strings.TrimSpace(val[:i])
			}
		}
		out[key] = val
	}
	return out, sc.Err()
}

func isKnown(k string) bool {
	for _, x := range known {
		if x == k {
			return true
		}
	}
	return false
}

const header = `# jsrelease configuration
# github_token: raises GitHub's API rate limit. A fine-grained token with no
#   permissions is enough; jsrelease only reads public data.
# nvd_api_key: optional; raises NVD's rate limit.
# Environment variables GITHUB_TOKEN and NVD_API_KEY take priority over this file.
`

// Save writes m to path, readable only by its owner, creating the folder if
// needed. The write is atomic: a temporary file is renamed over the old one.
func Save(path string, m map[string]string) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString(header)
	for _, k := range known {
		fmt.Fprintf(&b, "%s: %s\n", k, strconv.Quote(m[k]))
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		return err
	}
	if _, err = tmp.WriteString(b.String()); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// PermissionWarning returns a warning when the file can be read by other
// users (not checked on Windows, which uses different permissions).
func PermissionWarning(path string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm()&0o077 == 0 {
		return ""
	}
	return fmt.Sprintf("%s can be read by other users; run: chmod 600 %s", path, path)
}

// Keys are the keys in use and where each came from ("" when not set).
type Keys struct {
	GitHub, GitHubFrom string
	NVD, NVDFrom       string
}

// Resolve reads the config file at path (which may not exist) and applies
// the environment variables, which take priority.
func Resolve(path string) (Keys, error) {
	m, err := Load(path)
	if err != nil {
		return Keys{}, err
	}
	var k Keys
	if v := m[KeyGitHub]; v != "" {
		k.GitHub, k.GitHubFrom = v, "config file "+path
	}
	if v := m[KeyNVD]; v != "" {
		k.NVD, k.NVDFrom = v, "config file "+path
	}
	if v := os.Getenv(EnvGitHub); v != "" {
		k.GitHub, k.GitHubFrom = v, "environment variable "+EnvGitHub
	}
	if v := os.Getenv(EnvNVD); v != "" {
		k.NVD, k.NVDFrom = v, "environment variable "+EnvNVD
	}
	return k, nil
}

// ReadSecret reads one line from in. When in is a terminal, prompt is shown
// on out and what is typed is not echoed.
func ReadSecret(in io.Reader, out io.Writer, prompt string) (string, error) {
	f, isFile := in.(*os.File)
	term := false
	if isFile {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			term = true
		}
	}
	if term {
		fmt.Fprint(out, prompt)
		restore := disableEcho(f)
		defer func() {
			restore()
			fmt.Fprintln(out)
		}()
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
