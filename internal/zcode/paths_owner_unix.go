//go:build !windows

package zcode

import (
	"fmt"
	"os"
	"syscall"
)

func validateOwner(info os.FileInfo) error {
	if info == nil {
		return fmt.Errorf("%w: missing file info", ErrUnsafeStatePath)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(os.Geteuid()) != stat.Uid {
		return fmt.Errorf("%w: owner mismatch", ErrUnsafeStatePath)
	}
	return nil
}
