//go:build windows

package transaction

import (
	"os"

	"github.com/hcsolakoglu/zcode-auth/internal/windowssecure"
)

func privateFilePermissions(path string, info os.FileInfo) bool {
	return info != nil && windowssecure.IsOwnerOnly(path)
}

// Windows reports synthetic POSIX permission bits. Confidentiality is
// enforced by the owner-only ACL installed after each atomic write.
func validateRequestedMode(os.FileMode) error { return nil }

func hardenSensitiveDirectory(path string) error { return windowssecure.ProtectDirectory(path) }
