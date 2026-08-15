//go:build windows

package transaction

import "github.com/hcsolakoglu/zcode-account-manager/internal/windowssecure"

func hardenWindowsFile(path string) error { return windowssecure.ProtectFile(path) }
