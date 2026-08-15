//go:build windows

package zcode

import "github.com/hcsolakoglu/zcode-auth/internal/windowssecure"

func hardenStateDirectory(path string) error { return windowssecure.ProtectDirectory(path) }
func hardenStateFile(path string) error      { return windowssecure.ProtectFile(path) }
