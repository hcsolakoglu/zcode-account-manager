//go:build windows

package zcode

import "github.com/hcsolakoglu/zcode-account-manager/internal/windowssecure"

func hardenStateDirectory(path string) error { return windowssecure.ProtectDirectory(path) }
func hardenStateFile(path string) error      { return windowssecure.ProtectFile(path) }
