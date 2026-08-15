//go:build windows

package config

import (
	"os"
	"path/filepath"
)

func defaultDataBase(home string) string {
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		return base
	}
	return filepath.Join(home, "AppData", "Local")
}
