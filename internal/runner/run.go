// Package runner implements the jsrelease command.
package runner

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/config"
	"github.com/wantafanta/jsrelease/internal/datafile"
	"github.com/wantafanta/jsrelease/internal/logger"
	"github.com/wantafanta/jsrelease/internal/output"
	"github.com/wantafanta/jsrelease/internal/source/jquery"
)

// Version is the tool version, set by package main from the module version
// (go install …@v1.2.3) or a release build; "dev" for a source build.
var Version = "dev"

// displayVersion is "v1.2.3" for a release, "dev" otherwise.
func displayVersion() string {
	if Version != "" && Version[0] >= '0' && Version[0] <= '9' {
		return "v" + Version
	}
	return Version
}

// generatedBy is recorded in the data files; stored ETags are only reused by
// the same version, so an upgraded jsrelease re-reads its sources once.
func generatedBy() string { return "jsrelease " + Version }

// Default file names. They are looked up in the current working directory,
// next to the executable, then in the per-user data folder (see resolvePath).
const DefaultDataPath = datafile.DefaultName

// Run executes jsrelease with args (excluding the program name) and returns
// the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return run(args, stdout, stderr, nil)
}

// hooks lets tests point the updaters at local servers.
type hooks struct {
	stdin     io.Reader
	releases  *jquery.Config
	githubAPI string
	nvdAPI    string
	rawBase   string
}

func run(args []string, stdout, stderr io.Writer, h *hooks) int {
	if h == nil {
		h = &hooks{}
	}
	if len(args) == 0 {
		Usage(stdout)
		return 0
	}
	opts, err := ParseOptions(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			Usage(stdout)
			return 0
		}
		msg := err.Error()
		if !strings.HasSuffix(msg, ")") { // the message has no hint of its own
			msg += " (see -h)"
		}
		fmt.Fprintf(stderr, "%s %s\n", logger.Tag("ERR", earlyColor(stderr, args)), msg)
		return 2
	}
	if strings.EqualFold(strings.TrimSpace(opts.Columns), "list") {
		fmt.Fprint(stdout, output.ColumnsHelp())
		return 0
	}
	// Invalid -cols is an error even when nothing else was asked for.
	if opts.Columns != "" {
		valid, table := output.ReleaseColumnNames(), "release list"
		if opts.Check != "" {
			valid, table = output.CheckColumnNames(), "-check tables"
		}
		if _, err := output.ParseColumns(opts.Columns, valid, table); err != nil {
			fmt.Fprintf(stderr, "%s %v\n", logger.Tag("ERR", earlyColor(stderr, args)), err)
			return 2
		}
	}
	cfgPath := opts.Config
	if cfgPath == "" {
		var err error
		if cfgPath, err = config.DefaultPath(); err != nil && (opts.Keys || opts.SetKey != "") {
			fmt.Fprintf(stderr, "%s %v\n", logger.Tag("ERR", earlyColor(stderr, args)), err)
			return 1
		}
	} else if _, err := os.Stat(cfgPath); err != nil && opts.SetKey == "" {
		fmt.Fprintf(stderr, "%s -config: %v\n", logger.Tag("ERR", earlyColor(stderr, args)), err)
		return 2
	}
	if opts.Keys {
		return showKeys(cfgPath, stdout, stderr, args)
	}
	if opts.SetKey != "" {
		in := io.Reader(os.Stdin)
		if h.stdin != nil {
			in = h.stdin
		}
		return setKey(opts, cfgPath, in, stderr, args)
	}
	if !opts.Action {
		// e.g. "jsrelease -v": nothing to do, so show the help.
		Usage(stdout)
		return 0
	}
	if opts.Version {
		fmt.Fprintf(stdout, "jsrelease %s\n", displayVersion())
		return 0
	}
	log := logger.New(stderr, opts.Silent, opts.Verbose)
	if f, ok := stderr.(*os.File); ok {
		log.SetColor(logger.ColorWanted(f, opts.NoColor))
	}

	libs, err := catalog.ParseLibraries(opts.Library)
	if err != nil {
		log.Errorf("%v", err)
		return 2
	}
	if opts.Check != "" && len(libs) != 1 {
		log.Errorf("-check needs a single library: add -library core, migrate, ui or mobile")
		return 2
	}
	path := resolvePath(opts.Data, DefaultDataPath)
	vulnPath := path // one file holds both sections
	log.Debugf("Data file: %s", path)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	keys, kerr := config.Resolve(cfgPath)
	if kerr != nil {
		log.Errorf("%v", kerr)
		return 2
	}
	if w := config.PermissionWarning(cfgPath); w != "" {
		log.Warnf("%s", w)
	}
	if keys.GitHubFrom != "" {
		log.Debugf("Using the GitHub token from the %s", keys.GitHubFrom)
	}
	if keys.NVDFrom != "" {
		log.Debugf("Using the NVD API key from the %s", keys.NVDFrom)
	}
	opts.githubToken, opts.nvdKey = keys.GitHub, keys.NVD

	if opts.Update {
		// The two sources are updated independently: a failure in one does
		// not prevent or undo the other.
		failed := false
		newKeys, relSum, err := update(ctx, opts, path, path, log, h.releases, h.githubAPI, h.rawBase)
		if err != nil {
			log.Errorf("release update failed: %v", err)
			failed = true
		}
		vulnSum, err := updateVulns(ctx, opts, path, vulnPath, vulnPath, log, h.githubAPI, h.nvdAPI)
		if err != nil {
			log.Errorf("vulnerability update failed: %v", err)
			failed = true
		}
		summaries := func() {
			for _, s := range []string{relSum, vulnSum} {
				if s != "" {
					log.Infof("%s", s)
				}
			}
		}
		if opts.List || opts.Check != "" {
			// -update -list / -check: show those results instead of the table.
			summaries()
			if failed {
				return 1
			}
		} else {
			// The per-library table is the update's result; the summary
			// lines follow it.
			if err := stats(opts, path, vulnPath, libs, newKeys, stdout, log, false); err != nil {
				log.Errorf("%v", err)
				failed = true
			}
			log.Blank()
			summaries()
			if failed {
				return 1
			}
			return 0
		}
	}
	if opts.Stats {
		if err := stats(opts, path, vulnPath, libs, nil, stdout, log, true); err != nil {
			log.Errorf("%v", err)
			return 1
		}
		return 0
	}
	if opts.Check != "" {
		err = check(opts, path, vulnPath, libs[0], stdout, log)
	} else {
		err = list(opts, path, vulnPath, libs, stdout, log)
	}
	if err != nil {
		log.Errorf("%v", err)
		return 1
	}
	return 0
}

// earlyColor decides on colour for errors found before the switches are
// parsed.
func earlyColor(stderr io.Writer, args []string) bool {
	for _, a := range args {
		if a == "-nc" || a == "--nc" || a == "-no-color" || a == "--no-color" {
			return false
		}
	}
	f, ok := stderr.(*os.File)
	return ok && logger.ColorWanted(f, false)
}
