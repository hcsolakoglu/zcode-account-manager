//go:build windows

package profile

import "github.com/hcsolakoglu/zcode-auth/internal/windowssecure"

func hardenProfileDirectory(path string) error { return windowssecure.ProtectDirectory(path) }
func hardenProfileFile(path string) error      { return windowssecure.ProtectFile(path) }
