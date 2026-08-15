//go:build windows

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func readConfigFile(path string) ([]byte, error) {
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(filepath.Clean(path)), windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, fmt.Errorf("unsafe configuration file")
	}
	fileInfo, err := file.Stat()
	if err != nil || !fileInfo.Mode().IsRegular() || !configFileOwnerSafe(path, fileInfo) {
		return nil, fmt.Errorf("unsafe configuration file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err == nil && len(data) > 1<<20 {
		return nil, fmt.Errorf("configuration file exceeds size limit")
	}
	return data, err
}
