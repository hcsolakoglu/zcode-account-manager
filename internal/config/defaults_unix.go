//go:build linux

package config

import (
	"os"
	"os/exec"
	"path/filepath"
)

func defaultStateDir(home string) string {
	if base := os.Getenv("ZCODE_DATA_BASE_DIR"); base != "" {
		return filepath.Join(base, "v2")
	}
	return filepath.Join(home, ".zcode", "v2")
}

func defaultDesktopExecutable(home string) string {
	for _, candidate := range []string{
		filepath.Join(home, ".local", "bin", "zcode"),
		"/opt/ZCode/zcode",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if path, err := exec.LookPath("zcode"); err == nil {
		return path
	}
	// Keep an absolute, deterministic fallback for installation diagnostics.
	return filepath.Join(home, ".local", "bin", "zcode")
}

func defaultCLIExecutable(home string) string {
	for _, candidate := range []string{
		filepath.Join(home, ".zcode", "cli", "zcode"),
		filepath.Join(home, ".zcode", "cli", "bin", "zcode"),
		filepath.Join(home, ".local", "bin", "zcode-cli"),
		filepath.Join(home, ".local", "bin", "zcode"),
		"/opt/ZCode/zcode",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if path, err := exec.LookPath("zcode-cli"); err == nil {
		return path
	}
	if path, err := exec.LookPath("zcode"); err == nil {
		return path
	}
	// It is valid for the bundled CLI not to be installed; this path is only a
	// selector used by fail-closed process discovery.
	return filepath.Join(home, ".zcode", "cli", "zcode")
}
