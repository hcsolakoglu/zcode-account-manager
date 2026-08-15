//go:build windows

package config

import (
	"os"

	"github.com/hcsolakoglu/zcode-account-manager/internal/windowssecure"
)

func configPermissionsSafe(path string, info os.FileInfo) bool {
	return info != nil && windowssecure.IsOwnerOnly(path)
}
