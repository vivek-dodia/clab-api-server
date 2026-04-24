package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/srl-labs/clab-api-server/internal/serverversion"
)

func runVersionCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stdout, serverversion.FormatInfo(currentBuildInfo()))
		return 0
	}

	switch args[0] {
	case "-h", "--help", "help":
		printVersionHelp(stdout)
		return 0
	case "check":
		if hasHelpArg(args[1:]) {
			printVersionCheckHelp(stdout)
			return 0
		}

		result, err := serverversion.Check(ctx, version, serverversion.CheckOptions{})
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "Failed fetching latest version information")
			return 0
		}

		_, _ = fmt.Fprintln(stdout, result)
		return 0
	case "upgrade", "update":
		if hasHelpArg(args[1:]) {
			printVersionUpgradeHelp(stdout)
			return 0
		}

		if err := serverversion.Upgrade(ctx, serverversion.UpgradeOptions{Stdout: stdout, Stderr: stderr}); err != nil {
			_, _ = fmt.Fprintf(stderr, "%s\n", err)
			return 1
		}

		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown version command %q\n\n", args[0])
		printVersionHelp(stderr)
		return 2
	}
}

func currentBuildInfo() serverversion.BuildInfo {
	return serverversion.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}
}

func printVersionHelp(w io.Writer) {
	_, _ = fmt.Fprintln(w, strings.TrimSpace(`
Show clab-api-server version or upgrade

USAGE
  clab-api-server version [command]

COMMANDS
  check     Check if a new version of clab-api-server is available
  upgrade   Upgrade clab-api-server to latest available version
  update    Alias for upgrade
`))
}

func printVersionCheckHelp(w io.Writer) {
	_, _ = fmt.Fprintln(w, strings.TrimSpace(`
Check if a new version of clab-api-server is available

USAGE
  clab-api-server version check
`))
}

func printVersionUpgradeHelp(w io.Writer) {
	_, _ = fmt.Fprintln(w, strings.TrimSpace(`
Upgrade clab-api-server to latest available version

USAGE
  clab-api-server version upgrade

ALIASES
  update
`))
}

func hasHelpArg(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "help" {
			return true
		}
	}

	return false
}
