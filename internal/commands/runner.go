package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hcsolakoglu/zcode-auth/internal/config"
)

var ErrUsage = errors.New("invalid command usage")

// Runner is the process-level convenience entry point.  Tests that need
// deterministic state should construct an App with NewWithOptions and call
// App.Execute instead, injecting a StaticKeyProvider and fake process hooks.
func Runner(args []string, stdout, stderr io.Writer) error {
	return RunContext(context.Background(), args, stdout, stderr)
}

// RunContext is the signal-aware variant used by the installed executable.
func RunContext(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	app, err := New(cfg, nil, stdout, stderr)
	if err != nil {
		return err
	}
	return app.Execute(ctx, args)
}

// Run is kept as a conventional alias for callers embedding the CLI.
func Run(args []string, stdout, stderr io.Writer) error {
	return Runner(args, stdout, stderr)
}

// Execute dispatches one parsed command.  It deliberately avoids the
// standard flag package's global state so multiple isolated App instances can
// be exercised in one test process.
func (a *App) Execute(ctx context.Context, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(args) == 0 {
		return usageError("missing command")
	}
	if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		return a.printUsage()
	}
	command := args[0]
	values, flags, err := parseArgs(args[1:])
	if err != nil {
		return err
	}
	jsonOutput := flags["json"]
	switch command {
	case "list":
		if len(values) != 0 || hasUnexpected(flags, "json") {
			return usageError("list accepts only --json")
		}
		return a.List(jsonOutput)
	case "current":
		if len(values) != 0 || hasUnexpected(flags, "json") {
			return usageError("current accepts only --json")
		}
		return a.Current(jsonOutput)
	case "add":
		if len(values) != 1 || len(flags) != 0 {
			return usageError("add requires <alias>")
		}
		return a.Save(values[0], true)
	case "save":
		if len(values) != 1 || len(flags) != 0 {
			return usageError("save requires <alias>")
		}
		return a.Save(values[0], false)
	case "switch":
		if len(values) != 1 || hasUnexpected(flags, "restart") {
			return usageError("switch requires <alias> or - and optional --restart")
		}
		return a.Switch(ctx, values[0], flags["restart"])
	case "remove":
		if len(values) != 1 || len(flags) != 0 {
			return usageError("remove requires <alias>")
		}
		return a.Remove(values[0])
	case "logout":
		if len(values) != 0 || len(flags) != 0 {
			return usageError("logout accepts no arguments")
		}
		return a.Logout()
	case "login":
		if len(values) != 1 || len(flags) != 0 {
			return usageError("login requires <alias>")
		}
		return a.Login(ctx, values[0])
	case "backup":
		if len(values) != 0 || len(flags) != 0 {
			return usageError("backup accepts no arguments")
		}
		return a.Backup()
	case "backups":
		if len(values) != 0 || hasUnexpected(flags, "json") {
			return usageError("backups accepts only --json")
		}
		return a.ListBackups(jsonOutput)
	case "restore":
		if len(values) != 1 || len(flags) != 0 {
			return usageError("restore requires <backup>")
		}
		return a.Restore(values[0])
	case "doctor":
		if len(values) != 0 || hasUnexpected(flags, "repair", "json") {
			return usageError("doctor accepts --repair and/or --json")
		}
		return a.Doctor(flags["repair"], jsonOutput)
	default:
		return usageError("unknown command %q", command)
	}
}

func parseArgs(args []string) ([]string, map[string]bool, error) {
	values := make([]string, 0, len(args))
	flags := make(map[string]bool)
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") {
			name := strings.TrimPrefix(arg, "--")
			if name == "" || strings.Contains(name, "=") {
				return nil, nil, usageError("invalid option")
			}
			if flags[name] {
				return nil, nil, usageError("duplicate option --%s", name)
			}
			flags[name] = true
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			return nil, nil, usageError("invalid option")
		}
		values = append(values, arg)
	}
	return values, flags, nil
}

func hasUnexpected(flags map[string]bool, allowed ...string) bool {
	for name := range flags {
		ok := false
		for _, candidate := range allowed {
			if name == candidate {
				ok = true
				break
			}
		}
		if !ok {
			return true
		}
	}
	return false
}

func usageError(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrUsage, fmt.Sprintf(format, values...))
}

func (a *App) printUsage() error {
	_, err := fmt.Fprintln(a.Out, `Usage: zcode-auth <command> [options]

Commands:
  list [--json]
  current [--json]
  add <alias>
  save <alias>
  switch <alias>|- [--restart]
  remove <alias>
  logout
  login <alias>
  backup
  backups [--json]
  restore <backup-id>
  doctor [--repair] [--json]`)
	return err
}
