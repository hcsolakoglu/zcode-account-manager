//go:build !windows

package transaction

import (
	"fmt"
	"os"
)

func privateFilePermissions(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().Perm() == 0o600
}

func validateRequestedMode(mode os.FileMode) error {
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("insecure mode %04o", mode.Perm())
	}
	return nil
}

func hardenSensitiveDirectory(string) error { return nil }
