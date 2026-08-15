//go:build !windows

package transaction

import "os"

func replaceAtomic(temp, destination string) error { return os.Rename(temp, destination) }
