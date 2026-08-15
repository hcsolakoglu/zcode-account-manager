//go:build !windows

package profile

import (
	"os"
	"syscall"
)

func ownedByCurrentUser(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint32(os.Geteuid()) == stat.Uid
}
