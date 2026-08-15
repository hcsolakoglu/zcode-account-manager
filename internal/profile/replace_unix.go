//go:build !windows

package profile

import "os"

func replaceProfileFile(temp, destination string) error { return os.Rename(temp, destination) }
