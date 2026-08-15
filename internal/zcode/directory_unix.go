//go:build !windows

package zcode

func validateDirectoryComponent(string) error { return nil }
