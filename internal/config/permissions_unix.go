//go:build !windows

package config

import "os"

func configPermissionsSafe(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().Perm()&0o022 == 0
}
