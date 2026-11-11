// Command jsrelease lists the releases of popular JavaScript libraries with
// their release dates, support status and known vulnerabilities.
package main

import (
	_ "embed"
	"os"
	"runtime/debug"
	"strings"

	"github.com/wantafanta/jsrelease/internal/runner"
)

// The shipped data, built into the binary so an installed jsrelease works
// before its first update.
//
//go:embed jsrelease.json
var bundled []byte

// version is set by release builds (-ldflags "-X main.version=1.2.3").
var version string

func main() {
	runner.Version = buildVersion()
	runner.Bundled = bundled
	os.Exit(runner.Run(os.Args[1:], os.Stdout, os.Stderr))
}

// buildVersion is the release build's version, else the module version
// recorded by go install (v1.2.3 -> 1.2.3), else "dev".
func buildVersion() string {
	if version != "" {
		return strings.TrimPrefix(version, "v")
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return "dev"
}
