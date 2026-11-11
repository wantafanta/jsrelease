package runner

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/wantafanta/jsrelease/internal/config"
	"github.com/wantafanta/jsrelease/internal/logger"
)

// showKeys prints whether each key is set and copy-and-paste instructions
// for this system (-keys).
func showKeys(cfgPath string, stdout, stderr io.Writer, args []string) int {
	k, err := config.Resolve(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s %v\n", logger.Tag("ERR", earlyColor(stderr, args)), err)
		return 2
	}
	status := func(from string) string {
		if from == "" {
			return "not set"
		}
		return "set (" + from + ")"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "GitHub token: %s\n", status(k.GitHubFrom))
	fmt.Fprintf(&b, "NVD API key:  %s\n\n", status(k.NVDFrom))
	b.WriteString("A GitHub token raises GitHub's limit of 60 requests per hour. It needs no\npermissions: jsrelease only reads public data. Create one at\nhttps://github.com/settings/personal-access-tokens/new\nAn NVD API key is optional: https://nvd.nist.gov/developers/request-an-api-key\n\n")
	b.WriteString("Store them in the config file (input is hidden; the file is readable only by you):\n\n")
	b.WriteString("  jsrelease -set-key github\n  jsrelease -set-key nvd\n\n")
	fmt.Fprintf(&b, "  (file: %s)\n\n", cfgPath)
	b.WriteString("Or set them for this terminal session only:\n\n")
	if runtime.GOOS == "windows" {
		b.WriteString("  PowerShell:\n")
		b.WriteString("    $env:GITHUB_TOKEN = Read-Host -MaskInput \"GitHub token\"\n")
		b.WriteString("    $env:NVD_API_KEY  = Read-Host -MaskInput \"NVD API key\"\n\n")
		b.WriteString("  PowerShell, permanently for your user account (new terminals pick it up):\n")
		b.WriteString("    [Environment]::SetEnvironmentVariable(\"GITHUB_TOKEN\", (Read-Host -MaskInput \"GitHub token\"), \"User\")\n\n")
		b.WriteString("  cmd (the key is shown as you type it; prefer PowerShell or -set-key):\n")
		b.WriteString("    set GITHUB_TOKEN=<your token>\n")
	} else {
		b.WriteString("  read -rs GITHUB_TOKEN && export GITHUB_TOKEN\n")
		b.WriteString("  read -rs NVD_API_KEY && export NVD_API_KEY\n\n")
		b.WriteString("  (paste the key and press Enter; nothing is shown, and it isn't saved in your\n  shell history)\n")
	}
	b.WriteString("\nEnvironment variables take priority over the config file. Don't share or zip a\nfolder containing a config file with keys in it.\n")
	io.WriteString(stdout, b.String())
	return 0
}

// setKey stores or clears a key in the config file (-set-key).
func setKey(opts *Options, cfgPath string, in io.Reader, stderr io.Writer, args []string) int {
	color := earlyColor(stderr, args)
	if f, ok := stderr.(*os.File); ok {
		color = logger.ColorWanted(f, opts.NoColor)
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "%s %s\n", logger.Tag("ERR", color), fmt.Sprintf(format, a...))
		return 2
	}
	var key, label string
	switch strings.ToLower(opts.SetKey) {
	case "github", "github_token":
		key, label = config.KeyGitHub, "GitHub token"
	case "nvd", "nvd_api_key":
		key, label = config.KeyNVD, "NVD API key"
	default:
		return fail("-set-key: unknown key %q (use github or nvd)", opts.SetKey)
	}
	m, err := config.Load(cfgPath)
	if err != nil {
		return fail("%v", err)
	}
	if opts.Clear {
		delete(m, key)
	} else {
		v, err := config.ReadSecret(in, stderr, label+" (input hidden): ")
		if err != nil {
			return fail("%v", err)
		}
		if v == "" {
			return fail("no %s entered; nothing changed", label)
		}
		m[key] = v
	}
	if err := config.Save(cfgPath, m); err != nil {
		return fail("save %s: %v", cfgPath, err)
	}
	if !opts.Silent {
		what := "Saved the " + label + " to"
		if opts.Clear {
			what = "Removed the " + label + " from"
		}
		where := " (readable only by you)"
		if runtime.GOOS == "windows" {
			where = ""
		}
		fmt.Fprintf(stderr, "%s %s %s%s\n", logger.Tag("INF", color), what, cfgPath, where)
	}
	return 0
}
