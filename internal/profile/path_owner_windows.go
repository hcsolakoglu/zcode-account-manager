//go:build windows

package profile

import "fmt"

func validateProfilePathOwner(path string) error {
	if !ownedByCurrentUserPath(path) {
		return fmt.Errorf("%w: owner or reparse point cannot be verified", ErrUnsafePath)
	}
	return nil
}
