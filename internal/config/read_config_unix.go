//go:build !windows

package config

import (
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

func readConfigFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !configFileOwnerSafe(path, info) {
		return nil, fmt.Errorf("unsafe configuration file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("configuration file exceeds size limit")
	}
	return data, nil
}
