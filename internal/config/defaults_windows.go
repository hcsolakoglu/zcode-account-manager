//go:build windows

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
	for _, base := range []string{os.Getenv("LOCALAPPDATA"), os.Getenv("PROGRAMFILES")} {
		if base != "" {
			parts := []string{"ZCode", "ZCode.exe"}
			if base == os.Getenv("LOCALAPPDATA") {
				parts = []string{"Programs", "ZCode", "ZCode.exe"}
			}
			candidate := filepath.Join(append([]string{base}, parts...)...)
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	if path, err := exec.LookPath("ZCode.exe"); err == nil {
		return path
	}
	return filepath.Join(home, "AppData", "Local", "Programs", "ZCode", "ZCode.exe")
}

func defaultCLIExecutable(home string) string {
	candidates := []string{filepath.Join(home, ".zcode", "cli", "zcode.exe")}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		candidates = append(candidates, filepath.Join(base, "ZCode", "cli", "zcode.exe"), filepath.Join(base, "ZCode", "cli", "bin", "zcode.exe"), filepath.Join(base, "Programs", "ZCode", "ZCode.exe"))
	}
	if base := os.Getenv("PROGRAMFILES"); base != "" {
		candidates = append(candidates, filepath.Join(base, "ZCode", "ZCode.exe"))
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if path, err := exec.LookPath("zcode.exe"); err == nil {
		return path
	}
	return filepath.Join(home, ".zcode", "cli", "zcode.exe")
}
