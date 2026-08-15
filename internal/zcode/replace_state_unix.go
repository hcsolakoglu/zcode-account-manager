//go:build !windows

package zcode

import "os"

func replaceStateDocument(temp, destination string) error { return os.Rename(temp, destination) }
