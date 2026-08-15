//go:build windows

package config

import (
	"os"
	"path/filepath"
)

func defaultConfigBase(home string) string {
	if base := os.Getenv("APPDATA"); base != "" {
		return base
	}
	return filepath.Join(home, "AppData", "Roaming")
}
