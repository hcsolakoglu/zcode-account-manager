//go:build !windows

package config

func configDirectorySafe(string) error { return nil }
