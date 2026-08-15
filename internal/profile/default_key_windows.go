//go:build windows

package profile

func newDefaultKeyProvider() KeyProvider { return NewDPAPIKeyProvider() }
