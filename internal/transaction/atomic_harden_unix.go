//go:build !windows

package transaction

func hardenAtomicFile(string) error { return nil }
