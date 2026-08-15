//go:build linux

package zcode

import (
	"os"
	"os/exec"
	"path/filepath"
)

func defaultExecutablePath() string {
	home, _ := os.UserHomeDir()
	for _, candidate := range []string{filepath.Join(home, ".local", "bin", "zcode"), "/opt/ZCode/zcode"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if path, err := exec.LookPath("zcode"); err == nil {
		return path
	}
	return "/opt/ZCode/zcode"
}
