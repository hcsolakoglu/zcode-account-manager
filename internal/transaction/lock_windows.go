//go:build windows

package transaction

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/hcsolakoglu/zcode-auth/internal/windowssecure"
)

type LockMode int

const (
	Shared LockMode = iota
	Exclusive
)

type Lock struct {
	file   *os.File
	path   string
	unlock func() error
}

// Windows uses an exclusive byte-range lock with fail-closed reparse-point
// handling. The lock handle remains open for the full critical section.
func Acquire(path string, mode LockMode) (*Lock, error) {
	if mode != Shared && mode != Exclusive {
		return nil, fmt.Errorf("invalid lock mode %d", mode)
	}
	path, err := absolutePath(path)
	if err != nil {
		return nil, fmt.Errorf("lock path: %w", err)
	}
	if err := validateParentDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("lock parent: %w", err)
	}
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open lock %q: %w", path, err)
	}
	file := os.NewFile(uintptr(handle), path)
	closeWithError := func(cause error) (*Lock, error) { _ = file.Close(); return nil, cause }
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return closeWithError(fmt.Errorf("inspect lock %q: %w", path, err))
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return closeWithError(fmt.Errorf("lock %q is a reparse point", path))
	}
	if !ownedByCurrentUserPath(path) {
		return closeWithError(fmt.Errorf("lock %q owner cannot be verified", path))
	}
	if err := file.Chmod(0o600); err != nil {
		return closeWithError(fmt.Errorf("secure lock %q: %w", path, err))
	}
	if err := windowssecure.ProtectFile(path); err != nil {
		return closeWithError(fmt.Errorf("secure lock ACL %q: %w", path, err))
	}
	overlapped := new(windows.Overlapped)
	flags := uint32(0)
	if mode == Exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	if err := windows.LockFileEx(handle, flags, 0, 1, 0, overlapped); err != nil {
		return closeWithError(fmt.Errorf("lock %q: %w", path, err))
	}
	return &Lock{file: file, path: path, unlock: func() error { return windows.UnlockFileEx(handle, 0, 1, 0, overlapped) }}, nil
}

func AcquireShared(path string) (*Lock, error)    { return Acquire(path, Shared) }
func AcquireExclusive(path string) (*Lock, error) { return Acquire(path, Exclusive) }

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	var unlockErr error
	if l.unlock != nil {
		unlockErr = l.unlock()
	}
	closeErr := file.Close()
	if unlockErr != nil || closeErr != nil {
		return errors.Join(unlockErr, closeErr)
	}
	return nil
}

func validateParentDirectory(path string) error {
	path, err := absolutePath(path)
	if err != nil {
		return err
	}
	current := filepath.VolumeName(path) + string(filepath.Separator)
	remainder := path[len(current):]
	for remainder != "" {
		part := remainder
		if i := strings.IndexByte(remainder, '\\'); i >= 0 {
			part, remainder = remainder[:i], remainder[i+1:]
		} else {
			remainder = ""
		}
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || isReparsePoint(current) {
			return fmt.Errorf("unsafe lock parent %q", current)
		}
	}
	return nil
}

func isReparsePoint(path string) bool {
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(filepath.Clean(path)))
	return err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func absolutePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func ownedByCurrentUserPath(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	return err == nil && user != nil && user.User.Sid != nil && windows.EqualSid(owner, user.User.Sid)
}
