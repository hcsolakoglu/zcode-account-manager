//go:build windows

package transaction

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func createAtomicTemp(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	handle := windows.Handle(file.Fd())
	if err := windows.FlushFileBuffers(handle); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("flush atomic temporary file: %w", err)
	}
	return file, nil
}

func hardenAtomicFile(path string) error { return hardenWindowsFile(path) }

func syncParentPlatform(path string) error {
	// NTFS guarantees that ReplaceFile/MoveFileEx operates on the same volume;
	// the temporary file is flushed before rename. Directory handles cannot be
	// flushed portably, so a non-directory/reparse check is still required.
	info, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("atomic parent is not a real directory")
	}
	return nil
}
