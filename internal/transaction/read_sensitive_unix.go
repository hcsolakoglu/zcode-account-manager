//go:build !windows

package transaction

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readSensitivePlatform(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("sensitive path %q is not a regular file", path)
	}
	if err := checkOwner(info, path); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}
