//go:build windows

package config

import (
	"fmt"
	"golang.org/x/sys/windows"
	"path/filepath"
)

func configDirectorySafe(path string) error {
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(filepath.Clean(path)))
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("unsafe reparse-point directory %s", path)
	}
	return nil
}
