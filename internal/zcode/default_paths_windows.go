//go:build windows

package zcode

import (
	"os"
	"os/exec"
	"path/filepath"
)

func defaultExecutablePath() string {
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
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "AppData", "Local", "Programs", "ZCode", "ZCode.exe")
}
