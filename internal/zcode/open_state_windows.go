//go:build windows

package zcode

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func openStateRead(path string) (*os.File, error) {
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(filepath.Clean(path)), windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return nil, ErrUnsafeStatePath
	}
	if err := validateOwnerPath(path); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// Windows flushes file contents on the file handle; directory handles are not
// flushable in the same way as POSIX directory fsync. Rename durability is
// therefore provided by the flushed temporary file and atomic ReplaceFile.
func syncStateDirectory(string) error { return nil }
