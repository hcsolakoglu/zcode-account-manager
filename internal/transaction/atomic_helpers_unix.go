//go:build !windows

package transaction

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func createAtomicTemp(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func syncParentPlatform(path string) error {
	fd, err := unix.Open(filepath.Clean(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open parent directory %q: %w", path, err)
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory %q: %w", path, err)
	}
	return nil
}
