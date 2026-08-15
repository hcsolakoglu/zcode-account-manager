//go:build linux

package profile

func newDefaultKeyProvider() KeyProvider { return NewSecretToolKeyProvider() }
