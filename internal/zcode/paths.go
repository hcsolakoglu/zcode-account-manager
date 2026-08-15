// Package zcode contains the small, deliberately conservative adapter for
// ZCode's on-disk authentication state.  The adapter keeps the files opaque
// for writes; it only decrypts the two credential values needed to identify
// an authenticated account.
package zcode

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	// ErrStateNotFound indicates that an optional state file does not exist.
	ErrStateNotFound = os.ErrNotExist
	// ErrInvalidState is returned when a state document is not a JSON object.
	ErrInvalidState = errors.New("zcode state is not a JSON object")
	// ErrUnsafeStatePath indicates a symlink, non-regular file, or file owned
	// by a different local user.  The error intentionally contains no file
	// contents or credential values.
	ErrUnsafeStatePath = errors.New("zcode state path is unsafe")
	// ErrIdentityNotFound indicates that no stable account identity was found.
	ErrIdentityNotFound = errors.New("zcode account identity not found")
	// ErrNotAuthenticated indicates that the credential document is valid JSON
	// but does not represent a complete authenticated session.
	ErrNotAuthenticated = errors.New("zcode credentials are not authenticated")
	// ErrIdentityConflict indicates that a credential document exposes two
	// different stable identifiers for the same account.
	ErrIdentityConflict = errors.New("zcode account identity fields conflict")
	// ErrCredentialDecrypt is deliberately generic.  In particular, it never
	// includes an encrypted value, key, or plaintext credential in its message.
	ErrCredentialDecrypt = errors.New("zcode credential value could not be decrypted")
)

const maxIdentityBytes = 4096

func validateIdentityString(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxIdentityBytes || !utf8.ValidString(value) {
		return "", false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", false
		}
	}
	return value, true
}

// Paths describes the two account-scoped state files used by ZCode.  The
// default state directory is ~/.zcode/v2.  Executable is kept here because
// callers generally discover the binary and its state as one adapter.
type Paths struct {
	StateDir          string
	CredentialsPath   string
	TelemetryPath     string
	TelemetryLockPath string
	Executable        string
	CLIExecutable     string
}

// DefaultPaths returns paths for the current user's normal ZCode install.
// It does not access or modify either state file.
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("resolve home directory: %w", err)
	}
	base := os.Getenv("ZCODE_DATA_BASE_DIR")
	if base == "" {
		base = filepath.Join(home, ".zcode")
	}
	return PathsForStateDir(filepath.Join(base, "v2")), nil
}

// PathsForStateDir constructs paths beneath stateDir.  An empty executable
// means that process operations should be configured separately by the caller.
func PathsForStateDir(stateDir string) Paths {
	return Paths{
		StateDir:          stateDir,
		CredentialsPath:   filepath.Join(stateDir, "credentials.json"),
		TelemetryPath:     filepath.Join(stateDir, "telemetry-state.json"),
		TelemetryLockPath: filepath.Join(stateDir, "telemetry-state.lock"),
		Executable:        defaultExecutablePath(),
	}
}

// WithExecutable returns a copy with an explicitly selected ZCode executable.
func (p Paths) WithExecutable(executable string) Paths {
	p.Executable = executable
	return p
}

// WithCLIExecutable records the bundled CLI selector. It is never used to
// launch a CLI during account operations; it exists so shared-state ownership
// can be detected before mutation.
func (p Paths) WithCLIExecutable(executable string) Paths {
	p.CLIExecutable = executable
	return p
}

// ValidateSensitivePath verifies the final path component and every existing
// parent component without following a user-controlled symlink.  A missing
// final file is allowed only when allowMissing is true.  New files can safely
// be created after this check because the parent chain has also been checked.
func ValidateSensitivePath(path string, allowMissing bool) error {
	if path == "" {
		return fmt.Errorf("%w: empty path", ErrUnsafeStatePath)
	}

	clean := filepath.Clean(path)
	if err := validateParentChain(filepath.Dir(clean)); err != nil {
		return err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := validateOwner(info); err != nil {
		return err
	}
	if err := validateOwnerPath(clean); err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: expected regular file", ErrUnsafeStatePath)
	}
	return nil
}

// ValidateSensitiveDirectory applies the state-root ownership contract to a
// directory itself. ValidateSensitivePath checks existing parents for type and
// reparse safety, but intentionally cannot infer which parent is the user's
// application root; callers that own a directory tree must use this helper.
func ValidateSensitiveDirectory(path string, allowMissing bool) error {
	if path == "" {
		return fmt.Errorf("%w: empty directory path", ErrUnsafeStatePath)
	}
	clean := filepath.Clean(path)
	if err := validateParentChain(filepath.Dir(clean)); err != nil {
		return err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: expected directory", ErrUnsafeStatePath)
	}
	if err := validateDirectoryComponent(clean); err != nil {
		return err
	}
	if err := validateOwner(info); err != nil {
		return err
	}
	if err := validateOwnerPath(clean); err != nil {
		return err
	}
	return nil
}

func validateParentChain(path string) error {
	clean := filepath.Clean(path)
	// Build the chain from the root down.  Checking only the final parent would
	// still allow /tmp/attacker-link/credentials.json.
	var chain []string
	for current := clean; ; current = filepath.Dir(current) {
		chain = append(chain, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		info, err := os.Lstat(chain[i])
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// A caller creating a state directory may have missing
				// ancestors.  Existing ancestors are still checked.
				continue
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: expected directory parent", ErrUnsafeStatePath)
		}
		if err := validateDirectoryComponent(chain[i]); err != nil {
			return err
		}
		// System ancestors such as / and /home are normally root-owned. The
		// sensitive state root itself must belong to the invoking user.
		if chain[i] == clean {
			if err := validateOwner(info); err != nil {
				return err
			}
			if err := validateOwnerPath(chain[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

// CurrentUsername returns the username used by ZCode's fallback key derivation.
// It is exported so tests and callers that need to display diagnostics can use
// the same conservative lookup without exposing a credential value.
func CurrentUsername() string {
	if current, err := user.Current(); err == nil && current.Username != "" {
		return current.Username
	}
	if username := os.Getenv("USER"); username != "" {
		return username
	}
	return "unknown"
}
