//go:build windows

package commands

import (
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/hcsolakoglu/zcode-account-manager/internal/windowssecure"
)

func hardenCoordinatorFile(path string) error { return windowssecure.ProtectFile(path) }
func replaceCoordinatorFile(temp, destination string) error {
	return windows.MoveFileEx(windows.StringToUTF16Ptr(filepath.Clean(temp)), windows.StringToUTF16Ptr(filepath.Clean(destination)), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
