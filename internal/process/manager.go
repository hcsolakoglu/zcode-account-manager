package process

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Manager binds an executable selector to the generic process primitives.
// ZCode-specific naming remains in the adapter; this type is reusable by
// commands that already resolved the configured executable path.
type Manager struct {
	Executable  string
	Executables []string
	Scanner     Scanner
}

func NewManager(executable string) Manager {
	return Manager{Executable: executable, Executables: []string{executable}, Scanner: NewScanner()}
}

func NewMultiManager(executables ...string) Manager {
	m := Manager{Scanner: NewScanner()}
	for _, executable := range executables {
		if executable == "" {
			continue
		}
		m.Executables = append(m.Executables, executable)
	}
	if len(m.Executables) != 0 {
		m.Executable = m.Executables[0]
	}
	return m
}

func (m Manager) selectors() []string {
	if len(m.Executables) != 0 {
		return m.Executables
	}
	if m.Executable != "" {
		return []string{m.Executable}
	}
	return nil
}

func (m Manager) Detect() ([]Info, error) {
	type processIdentity struct {
		pid       int
		startTime uint64
	}
	seen := make(map[processIdentity]struct{})
	result := make([]Info, 0)
	selectors := m.selectors()
	// A desktop and bundled CLI launched from the same executable cannot be
	// distinguished by image path alone. Treat every matching process as a CLI
	// owner in that configuration; stopping it would be an unsafe guess.
	duplicateSelector := make(map[string]bool)
	for index, selector := range selectors {
		clean := selectorIdentity(selector)
		for _, prior := range selectors[:index] {
			if selectorIdentity(prior) == clean {
				duplicateSelector[clean] = true
				break
			}
		}
	}
	for index, executable := range selectors {
		items, err := m.Scanner.List(executable)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			identity := processIdentity{pid: item.PID, startTime: item.StartTime}
			if _, ok := seen[identity]; ok {
				continue
			}
			seen[identity] = struct{}{}
			if duplicateSelector[selectorIdentity(executable)] {
				item.Product = classifySharedImage(item.Name)
			} else if index == 0 {
				item.Product = "desktop"
			} else {
				item.Product = "cli"
			}
			result = append(result, item)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PID < result[j].PID })
	return result, nil
}

func selectorIdentity(path string) string {
	identity := filepath.Clean(path)
	if resolved, err := canonicalPath(path); err == nil {
		identity = resolved
	}
	if runtime.GOOS == "windows" {
		identity = strings.ToLower(identity)
	}
	return identity
}

func classifySharedImage(name string) string {
	// Linux exposes the task comm name independently of the executable image;
	// observed ZCode desktop/CLI processes use ZCode and zcode-cli. Toolhelp on
	// Windows only returns the image basename, and macOS has no verified
	// equivalent mode marker, so a shared image is ambiguous there.
	if runtime.GOOS != "linux" {
		return "cli"
	}
	switch name {
	case "ZCode", "ZCode.exe":
		return "desktop"
	case "zcode-cli", "zcode-cli.exe":
		return "cli"
	default:
		// Same image with an unknown native process name is ambiguous.
		// Refuse to stop it rather than guess.
		return "cli"
	}
}

func (m Manager) Stop(ctx context.Context, info Info, options StopOptions) error {
	executable := info.Executable
	if executable == "" {
		executable = m.Executable
	}
	return m.Scanner.Stop(ctx, info, executable, options)
}

func (m Manager) Start(options StartOptions) (*os.Process, error) {
	return Start(m.Executable, options)
}
