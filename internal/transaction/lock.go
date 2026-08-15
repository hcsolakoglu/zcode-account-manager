// Package transaction contains the filesystem primitives used to rotate
// ZCode's account-scoped state.  The package intentionally does not know how
// credentials are encrypted; callers must provide encrypted payloads for
// anything that is persisted as a snapshot.
//go:build !windows

package transaction

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// LockMode controls the flock operation used by Acquire.
type LockMode int

const (
	// Shared permits concurrent readers, while still excluding an exclusive
	// transaction.
	Shared LockMode = iota
	// Exclusive excludes both readers and writers.
	Exclusive
)

// Lock is an advisory process lock.  The descriptor remains open for the
// lifetime of the lock; closing it releases the flock.
type Lock struct {
	file *os.File
	path string
}

// Acquire opens path as a private, owner-checked lock file and acquires a
// shared or exclusive advisory flock.  The lock file is never followed when
// opening it, and unexpected symlinks and foreign ownership are rejected.
//
// The caller must call Close.  A lock file is deliberately retained on disk:
// flock state is associated with the open descriptor, not with its directory
// entry, so removing it would make concurrent lock paths diverge.
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

	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %q: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	closeWithError := func(cause error) (*Lock, error) {
		_ = file.Close()
		return nil, cause
	}

	// O_NOFOLLOW protects the final component during open.  Verify the opened
	// inode too, so a caller can never accidentally use a directory, FIFO, or
	// a file owned by another uid as the lock.
	info, err := file.Stat()
	if err != nil {
		return closeWithError(fmt.Errorf("stat lock %q: %w", path, err))
	}
	if !info.Mode().IsRegular() {
		return closeWithError(fmt.Errorf("lock %q is not a regular file", path))
	}
	if err := checkOwner(info, path); err != nil {
		return closeWithError(err)
	}
	if err := file.Chmod(0o600); err != nil {
		return closeWithError(fmt.Errorf("chmod lock %q: %w", path, err))
	}

	flock := unix.LOCK_SH
	if mode == Exclusive {
		flock = unix.LOCK_EX
	}
	if err := unix.Flock(int(file.Fd()), flock); err != nil {
		return closeWithError(fmt.Errorf("flock %q: %w", path, err))
	}
	return &Lock{file: file, path: path}, nil
}

// AcquireShared acquires a shared lock.
func AcquireShared(path string) (*Lock, error) { return Acquire(path, Shared) }

// AcquireExclusive acquires an exclusive lock.
func AcquireExclusive(path string) (*Lock, error) { return Acquire(path, Exclusive) }

// Close releases the flock and closes the descriptor.  It is safe to call
// Close more than once.
func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		closeErr := file.Close()
		if closeErr != nil {
			return errors.Join(fmt.Errorf("unlock %q: %w", l.path, err), closeErr)
		}
		return fmt.Errorf("unlock %q: %w", l.path, err)
	}
	return file.Close()
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

// validateParentDirectory rejects symlinked parent directories.  Sensitive
// state is normally under a user-owned XDG directory; checking each existing
// component catches a symlink introduced anywhere in that path without
// requiring /tmp or other system roots to be owned by the current user.
func validateParentDirectory(path string) error {
	path, err := absolutePath(path)
	if err != nil {
		return err
	}
	parts := splitAbsolute(path)
	current := string(filepath.Separator)
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				// The final directory may be created by the caller.  Once a
				// component is missing there cannot be a trusted existing
				// component farther down this path.
				return nil
			}
			return fmt.Errorf("lstat %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symlink", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("path component %q is not a directory", current)
		}
	}
	return nil
}

func splitAbsolute(path string) []string {
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) {
		return nil
	}
	clean = clean[1:]
	parts := make([]string, 0, 4)
	for clean != "" {
		part := clean
		if index := stringIndexByte(clean, filepath.Separator); index >= 0 {
			part, clean = clean[:index], clean[index+1:]
		} else {
			clean = ""
		}
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func stringIndexByte(value string, separator byte) int {
	for index := 0; index < len(value); index++ {
		if value[index] == separator {
			return index
		}
	}
	return -1
}

func checkOwner(info os.FileInfo, path string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("stat %q has no owner information", path)
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%s %q is owned by uid %d, current uid is %d", "file", path, stat.Uid, os.Getuid())
	}
	return nil
}

func validateTarget(path string) (os.FileInfo, error) {
	path, err := absolutePath(path)
	if err != nil {
		return nil, err
	}
	if err := validateParentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("lstat %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("sensitive path %q is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("sensitive path %q is not a regular file", path)
	}
	if err := checkOwner(info, path); err != nil {
		return nil, err
	}
	return info, nil
}
