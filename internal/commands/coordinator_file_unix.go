//go:build !windows

package commands

import "os"

func hardenCoordinatorFile(string) error { return nil }
func replaceCoordinatorFile(temp, destination string) error {
	return os.Rename(temp, destination)
}
