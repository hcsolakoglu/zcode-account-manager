//go:build windows

package transaction

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func checkOwner(info os.FileInfo, path string) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !ownedByCurrentUserPath(path) {
		return fmt.Errorf("sensitive path %q owner cannot be verified", path)
	}
	return nil
}

func validateTarget(path string) (os.FileInfo, error) {
	path, err := absolutePath(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("lstat %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || isReparsePoint(path) {
		return nil, fmt.Errorf("sensitive path %q is not a regular file", path)
	}
	if !ownedByCurrentUserPath(path) {
		return nil, fmt.Errorf("sensitive path %q owner cannot be verified", path)
	}
	if err := validateParentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return info, nil
}
