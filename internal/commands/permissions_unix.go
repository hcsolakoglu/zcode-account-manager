//go:build !windows

package commands

import "os"

func commandPathSecure(_ string, info os.FileInfo) bool {
	if info == nil {
		return false
	}
	if info.IsDir() {
		return info.Mode().Perm()&0o077 == 0
	}
	return info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0
}

func repairCommandPath(path string, info os.FileInfo) error {
	if info.IsDir() {
		return os.Chmod(path, 0o700)
	}
	return os.Chmod(path, 0o600)
}

func hardenCommandDirectory(string) error { return nil }
