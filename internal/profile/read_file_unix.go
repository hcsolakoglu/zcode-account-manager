//go:build !windows

package profile

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readProfileFilePlatform(path string, maxBytes int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !ownedByCurrentUser(info) {
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
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read profile store file: %w", err)
	}
	return data, nil
}
