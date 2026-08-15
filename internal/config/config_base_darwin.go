//go:build darwin

package config

import (
	"os"
	"path/filepath"
)

func defaultConfigBase(home string) string {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return base
	}
	return filepath.Join(home, "Library", "Application Support")
}
