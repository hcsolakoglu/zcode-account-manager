//go:build !windows

package zcode

func hardenStateDirectory(string) error { return nil }
func hardenStateFile(string) error      { return nil }
