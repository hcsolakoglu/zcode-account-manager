package profile

import "errors"

// Sentinel errors returned by Store. Callers can use errors.Is without
// needing to inspect (or accidentally print) a lower-level error.
var (
	ErrNotFound              = errors.New("profile not found")
	ErrInvalidAlias          = errors.New("invalid profile alias")
	ErrInvalidIdentity       = errors.New("invalid account identity")
	ErrDuplicateIdentity     = errors.New("account identity already has a profile")
	ErrAliasIdentityMismatch = errors.New("profile alias belongs to another account")
	ErrCorrupt               = errors.New("profile store data is corrupt")
	ErrAuthentication        = errors.New("profile authentication failed")
	ErrUnsupportedVersion    = errors.New("unsupported profile store version")
	ErrInvalidKey            = errors.New("invalid profile encryption key")
	ErrKeyUnavailable        = errors.New("profile encryption key unavailable")
	ErrInvalidBundle         = errors.New("invalid profile session bundle")
	ErrInvalidPurpose        = errors.New("invalid payload purpose")
	ErrPayloadTooLarge       = errors.New("payload exceeds size limit")
	ErrUnsafePath            = errors.New("unsafe profile store path")
	ErrOrphanedProfile       = errors.New("orphaned profile data")
	ErrProfileJournal        = errors.New("invalid profile transaction journal")
)
