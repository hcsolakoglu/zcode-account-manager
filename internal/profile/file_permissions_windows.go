//go:build windows

package profile

import (
	"github.com/hcsolakoglu/zcode-account-manager/internal/windowssecure"
	"os"
)

func privateFilePermissions(path string, info os.FileInfo) bool {
	return info != nil && windowssecure.IsOwnerOnly(path)
}
