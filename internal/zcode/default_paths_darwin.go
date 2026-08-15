//go:build darwin

package zcode

import (
	"os"
	"os/exec"
)

func defaultExecutablePath() string {
	const app = "/Applications/ZCode.app/Contents/MacOS/ZCode"
	if _, err := os.Stat(app); err == nil {
		return app
	}
	if path, err := exec.LookPath("zcode"); err == nil {
		return path
	}
	return app
}
