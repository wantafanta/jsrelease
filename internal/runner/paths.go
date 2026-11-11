package runner

import (
	"os"
	"path/filepath"
)

// resolvePath returns the path of a data file. Without an explicit flag
// value, the first existing of ./<name>, <executable dir>/<name> and
// <user data folder>/<name> is used; if none exists, the user data folder
// (where -update creates it; until then the bundled data is read).
func resolvePath(flagValue, name string) string {
	if flagValue != "" {
		return flagValue
	}
	dirs := []string{""}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		dirs = append(dirs, filepath.Dir(exe))
	}
	if ud, err := userDataDir(); err == nil {
		dirs = append(dirs, ud)
	}
	for _, d := range dirs {
		if c := filepath.Join(d, name); exists(c) {
			return c
		}
	}
	if ud, err := userDataDir(); err == nil {
		return filepath.Join(ud, name)
	}
	return name
}

func exists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
