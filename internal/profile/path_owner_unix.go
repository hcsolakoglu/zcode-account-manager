//go:build !windows

package profile

func validateProfilePathOwner(string) error { return nil }
