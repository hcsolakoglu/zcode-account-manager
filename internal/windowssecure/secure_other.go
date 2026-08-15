//go:build !windows

package windowssecure

// These functions are not used by non-Windows backends. Keeping the package
// buildable on every host lets repository-wide tooling enumerate all packages
// without introducing a platform-specific import exception.
func ProtectFile(string) error      { return nil }
func ProtectDirectory(string) error { return nil }
