//go:build windows

package profile

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func readProfileFilePlatform(path string, maxBytes int64) ([]byte, error) {
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(filepath.Clean(path)), windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || !ownedByCurrentUserPath(path) {
		return nil, ErrUnsafePath
	}
	fileInfo, err := file.Stat()
	if err != nil || !fileInfo.Mode().IsRegular() {
		return nil, ErrUnsafePath
	}
	if maxBytes > 0 {
		data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxBytes {
			return nil, ErrCorrupt
		}
		return data, nil
	}
	return io.ReadAll(file)
}
