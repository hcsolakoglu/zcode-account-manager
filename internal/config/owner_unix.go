//go:build !windows

package config

import (
	"os"
	"syscall"
)

func configFileOwnerSafe(_ string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
