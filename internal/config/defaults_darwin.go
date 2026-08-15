//go:build darwin

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

func defaultDesktopExecutable(string) string {
	const app = "/Applications/ZCode.app/Contents/MacOS/ZCode"
	if _, err := os.Stat(app); err == nil {
		return app
	}
	if path, err := exec.LookPath("zcode"); err == nil {
		return path
	}
	return app
}

func defaultCLIExecutable(home string) string {
	for _, candidate := range []string{
		filepath.Join(home, ".zcode", "cli", "zcode"),
		filepath.Join(home, ".zcode", "cli", "bin", "zcode"),
		filepath.Join(home, ".local", "bin", "zcode-cli"),
		"/Applications/ZCode.app/Contents/MacOS/ZCode",
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
	return filepath.Join(home, ".zcode", "cli", "zcode")
}
