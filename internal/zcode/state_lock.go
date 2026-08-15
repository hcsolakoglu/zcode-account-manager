package zcode

import (
	"errors"
	"os"
)

var (
	ErrSharedStateBusy = errors.New("shared ZCode state is owned by another process")
	ErrUnsafeStateLock = errors.New("shared ZCode state lock cannot be verified")
)

// CheckSharedStateLock performs a non-mutating probe of ZCode's own lock.
// An absent lock is normal. A held lock, malformed lock, or unverifiable
// owner blocks any state mutation; stale lock cleanup is intentionally left to
// ZCode so this CLI never guesses whether a lock is abandoned.
func CheckSharedStateLock(paths Paths) error {
	lockPath := paths.TelemetryLockPath
	if lockPath == "" && paths.StateDir != "" {
		lockPath = paths.StateDir + string(pathSeparator()) + "telemetry-state.lock"
	}
	if lockPath == "" {
		return ErrUnsafeStateLock
	}
	if paths.StateDir != "" {
		if err := ValidateSensitiveDirectory(paths.StateDir, true); err != nil {
			return ErrUnsafeStateLock
		}
	}
	if err := ValidateSensitivePath(lockPath, true); err != nil {
		return ErrUnsafeStateLock
	}
	if _, err := os.Lstat(lockPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return ErrUnsafeStateLock
	}
	// ZCode's lock implementation is not guaranteed to use a native flock or
	// byte-range lock on every release/platform. Mere existence therefore
	// means ownership cannot be disproved. ZCode itself owns stale-lock cleanup.
	return ErrSharedStateBusy
}
