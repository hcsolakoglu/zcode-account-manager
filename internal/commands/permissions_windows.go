//go:build windows

package commands

import (
	"os"

	"github.com/hcsolakoglu/zcode-account-manager/internal/windowssecure"
)

func commandPathSecure(path string, info os.FileInfo) bool {
	return info != nil && windowssecure.IsOwnerOnly(path)
}

func repairCommandPath(path string, info os.FileInfo) error {
	if info.IsDir() {
		return windowssecure.ProtectDirectory(path)
	}
	return windowssecure.ProtectFile(path)
}

func hardenCommandDirectory(path string) error { return windowssecure.ProtectDirectory(path) }
