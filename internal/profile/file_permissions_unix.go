//go:build !windows

package profile

import "os"

func privateFilePermissions(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().Perm() == privateFileMode.Perm()
}
