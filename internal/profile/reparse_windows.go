//go:build windows

package profile

import (
	"golang.org/x/sys/windows"
	"path/filepath"
)

func profileDirectoryReparse(path string) bool {
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(filepath.Clean(path)))
	return err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
