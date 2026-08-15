//go:build windows

package transaction

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func replaceAtomic(temp, destination string) error {
	// ReplaceFile preserves the destination's ACL and is atomic on the same
	// NTFS volume. If the destination is absent, MoveFileEx handles first use.
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if _, err := os.Stat(destination); err == nil {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(windows.StringToUTF16Ptr(filepath.Clean(temp)), windows.StringToUTF16Ptr(filepath.Clean(destination)), flags)
}
