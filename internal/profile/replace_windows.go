//go:build windows

package profile

import (
	"golang.org/x/sys/windows"
	"path/filepath"
)

func replaceProfileFile(temp, destination string) error {
	return windows.MoveFileEx(windows.StringToUTF16Ptr(filepath.Clean(temp)), windows.StringToUTF16Ptr(filepath.Clean(destination)), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
