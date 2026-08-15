//go:build windows

package zcode

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func validateDirectoryComponent(path string) error {
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(filepath.Clean(path)))
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: reparse-point directory", ErrUnsafeStatePath)
	}
	return nil
}
