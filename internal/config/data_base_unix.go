//go:build linux

package config

import (
	"os"
	"path/filepath"
)

func defaultDataBase(home string) string {
	if base := os.Getenv("XDG_DATA_HOME"); base != "" {
		return base
	}
	return filepath.Join(home, ".local", "share")
}
