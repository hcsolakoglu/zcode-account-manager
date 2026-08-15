//go:build !windows

package profile

func hardenProfileDirectory(string) error { return nil }
func hardenProfileFile(string) error      { return nil }
