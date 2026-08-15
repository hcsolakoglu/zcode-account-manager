//go:build !windows

package profile

func profileDirectoryReparse(string) bool { return false }
