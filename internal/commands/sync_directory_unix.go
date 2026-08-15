//go:build !windows

package commands

import "os"

func syncDirectoryPlatform(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
