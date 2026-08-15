package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	privateDirMode  os.FileMode = 0o700
	privateFileMode os.FileMode = 0o600
	// These bounds are deliberately conservative for opaque JSON state. They
	// prevent an attacker-controlled registry/profile path from causing an
	// unbounded allocation before authentication and JSON validation.
	maxRegistryBytes    int64 = 1 << 20
	maxProfileFileBytes int64 = 32 << 20
	// A profile journal contains at most one old encrypted profile blob plus
	// the small registry snapshot.  Keep a generous bound to prevent a
	// tampered journal from causing an unbounded allocation before recovery.
	maxProfileJournalBytes int64 = maxProfileFileBytes*2 + maxRegistryBytes
	maxCredentialsBytes    int   = 8 << 20
	maxTelemetryBytes      int   = 8 << 20
)

func ensurePrivateDir(path string) error {
	if path == "" {
		return ErrUnsafePath
	}
	if err := validateDirectoryChain(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, privateDirMode); err != nil {
		return fmt.Errorf("create profile store directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect profile store directory: %w", err)
	}
	if err := validateOwnerAndType(info, true); err != nil {
		return err
	}
	if err := validateProfilePathOwner(path); err != nil {
		return err
	}
	// Tightening an existing directory is safe and makes upgrades from an
	// earlier release conform to the store's private-directory contract.
	if info.Mode().Perm() != privateDirMode.Perm() {
		if err := os.Chmod(path, privateDirMode); err != nil {
			return fmt.Errorf("secure profile store directory: %w", err)
		}
	}
	if err := hardenProfileDirectory(path); err != nil {
		return fmt.Errorf("secure profile store directory ACL: %w", err)
	}
	return nil
}

// validateDirectoryChain rejects any existing symlink/non-directory ancestor
// before MkdirAll can follow it. System ancestors may be root-owned; ownership
// is enforced for the sensitive directory itself after creation.
func validateDirectoryChain(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ErrUnsafePath
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(abs), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || profileDirectoryReparse(current) {
			return ErrUnsafePath
		}
	}
	return nil
}

func validateOwnerAndType(info os.FileInfo, directory bool) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafePath
	}
	if directory {
		if !info.IsDir() {
			return ErrUnsafePath
		}
	} else if !info.Mode().IsRegular() {
		return ErrUnsafePath
	}
	if !ownedByCurrentUser(info) {
		return ErrUnsafePath
	}
	return nil
}

func secureReadFile(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validateOwnerAndType(info, false); err != nil {
		return nil, err
	}
	if err := validateProfilePathOwner(path); err != nil {
		return nil, err
	}
	if !privateFilePermissions(path, info) {
		return nil, ErrUnsafePath
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, ErrCorrupt
	}
	b, err := readProfileFilePlatform(path, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("read profile store file: %w", err)
	}
	return b, nil
}

// secureWriteFile writes a complete file to a private temporary sibling,
// syncs it, and atomically renames it over the destination. A destination
// symlink or non-regular file is always rejected before replacement.
func secureWriteFile(path string, data []byte) error {
	parent := filepath.Dir(path)
	if err := ensurePrivateDir(parent); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if err := validateOwnerAndType(info, false); err != nil {
			return err
		}
		if err := validateProfilePathOwner(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect profile store file: %w", err)
	}

	tmp, err := os.CreateTemp(parent, ".zcode-auth-tmp-")
	if err != nil {
		return fmt.Errorf("create profile store temporary file: %w", err)
	}
	tmpName := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(privateFileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure profile store temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write profile store file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync profile store file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close profile store file: %w", err)
	}
	if err := hardenProfileFile(tmpName); err != nil {
		return fmt.Errorf("secure profile store file ACL: %w", err)
	}
	if err := replaceProfileFile(tmpName, path); err != nil {
		return fmt.Errorf("replace profile store file: %w", err)
	}
	removeTemp = false
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("sync profile store directory: %w", err)
	}
	return nil
}

func secureRemoveFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := validateOwnerAndType(info, false); err != nil {
		return err
	}
	if err := validateProfilePathOwner(path); err != nil {
		return err
	}
	if !privateFilePermissions(path, info) {
		return ErrUnsafePath
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove profile store file: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync profile store directory: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	return syncDirectoryPlatform(path)
}

func profileFileName(id string) string {
	return id + ".enc"
}

func validProfileID(id string) bool {
	if id == "" || id == "." || id == ".." || len(id) > 128 {
		return false
	}
	if strings.ContainsAny(id, `/\\`) {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func readDirEntries(path string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func copyBytes(b []byte) []byte {
	return append([]byte(nil), b...)
}
