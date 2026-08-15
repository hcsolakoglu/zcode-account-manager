//go:build darwin

package profile

func newDefaultKeyProvider() KeyProvider { return NewKeychainKeyProvider() }
