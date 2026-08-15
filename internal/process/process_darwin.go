//go:build darwin

package process

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	ErrProcessNotFound = errors.New("process not found")
	ErrProcessChanged  = errors.New("process identity changed")
	ErrStopTimeout     = errors.New("process did not exit before timeout")
	ErrForceRequired   = errors.New("force termination was not requested")
)

type Info struct {
	PID        int
	Executable string
	Product    string
	Name       string
	UID        uint32
	StartTime  uint64
}

type Scanner struct {
	ProcRoot string
	SelfPID  int
}

func NewScanner() Scanner                    { return Scanner{SelfPID: os.Getpid()} }
func List(executable string) ([]Info, error) { return NewScanner().List(executable) }
func Find(executable string) ([]Info, error) { return List(executable) }

func (s Scanner) List(executable string) ([]Info, error) {
	items, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	result := make([]Info, 0)
	for _, item := range items {
		pid := int(item.Proc.P_pid)
		if pid <= 0 || pid == s.SelfPID || item.Eproc.Ucred.Uid != uint32(unix.Getuid()) {
			continue
		}
		info, ok := darwinSnapshot(pid, item.Eproc.Ucred.Uid, item.Proc.P_starttime, darwinComm(item))
		if !ok {
			if strings.EqualFold(filepath.Base(executable), darwinComm(item)) {
				return nil, fmt.Errorf("cannot verify process %d identity", pid)
			}
			continue
		}
		if MatchesExecutable(executable, info.Executable) {
			result = append(result, info)
		}
	}
	return result, nil
}

func darwinComm(item unix.KinfoProc) string {
	return strings.TrimRight(string(item.Proc.P_comm[:]), "\x00")
}

func darwinSnapshot(pid int, uid uint32, started unix.Timeval, name string) (Info, bool) {
	path, err := processPath(pid)
	if err != nil || path == "" {
		return Info{}, false
	}
	start := uint64(started.Sec)*1_000_000 + uint64(started.Usec)
	if start == 0 {
		return Info{}, false
	}
	return Info{PID: pid, UID: uid, Executable: path, Name: name, StartTime: start}, true
}

func processPath(pid int) (string, error) {
	// proc_info(PROC_INFO_CALL_PIDINFO, ..., PROC_PIDPATHINFO) returns the
	// executable image path without exposing command-line arguments. The
	// latter can contain tokens and also cannot be safely split when an .app
	// path contains spaces.
	const (
		procInfoCallPIDInfo = 2
		procPIDPathInfo     = 11
		procPIDPathMax      = 4096
	)
	buffer := make([]byte, procPIDPathMax)
	read, _, errno := unix.Syscall6(
		unix.SYS_PROC_INFO,
		procInfoCallPIDInfo,
		uintptr(pid),
		procPIDPathInfo,
		0,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if errno != 0 {
		return "", errno
	}
	if read == 0 || read > uintptr(len(buffer)) {
		return "", fmt.Errorf("empty process path")
	}
	pathBytes := buffer[:read]
	if end := strings.IndexByte(string(pathBytes), 0); end >= 0 {
		pathBytes = pathBytes[:end]
	}
	path := strings.TrimSpace(string(pathBytes))
	if path == "" {
		return "", fmt.Errorf("empty process path")
	}
	return path, nil
}

func MatchesExecutable(expected, actual string) bool {
	if expected == "" || actual == "" {
		return false
	}
	if strings.ContainsRune(expected, filepath.Separator) {
		expectedPath, expectedErr := canonicalPath(expected)
		actualPath, actualErr := canonicalPath(actual)
		return expectedErr == nil && actualErr == nil && expectedPath == actualPath
	}
	return filepath.Base(actual) == expected
}
func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, e := filepath.EvalSymlinks(abs); e == nil {
		abs = resolved
	}
	return filepath.Clean(abs), nil
}

func (s Scanner) IsAlive(info Info, expected string) bool {
	items, err := s.List(expected)
	if err != nil {
		return false
	}
	for _, current := range items {
		if current.PID == info.PID && current.UID == info.UID && current.StartTime == info.StartTime && MatchesExecutable(expected, current.Executable) {
			return true
		}
	}
	return false
}

type StopOptions struct {
	Timeout      time.Duration
	PollInterval time.Duration
	Force        bool
}

func normalizeStopOptions(o StopOptions) StopOptions {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 50 * time.Millisecond
	}
	return o
}
func (s Scanner) Stop(ctx context.Context, info Info, expected string, options StopOptions) error {
	o := normalizeStopOptions(options)
	if ctx == nil {
		ctx = context.Background()
	}
	if info.PID <= 0 || info.PID == os.Getpid() {
		return ErrProcessNotFound
	}
	if !s.IsAlive(info, expected) {
		return nil
	}
	if err := s.signal(info, expected, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if s.waitExited(ctx, info, expected, o.Timeout, o.PollInterval) {
		return nil
	}
	if !o.Force {
		return ErrStopTimeout
	}
	if !s.IsAlive(info, expected) {
		return nil
	}
	if err := s.signal(info, expected, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if s.waitExited(ctx, info, expected, o.Timeout, o.PollInterval) {
		return nil
	}
	return ErrStopTimeout
}
func (s Scanner) signal(info Info, expected string, signal syscall.Signal) error {
	if !s.IsAlive(info, expected) {
		return ErrProcessChanged
	}
	return unix.Kill(info.PID, signal)
}
func (s Scanner) waitExited(ctx context.Context, info Info, expected string, timeout, interval time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if !s.IsAlive(info, expected) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		case <-ticker.C:
		}
	}
}
func Stop(ctx context.Context, info Info, expected string, options StopOptions) error {
	return NewScanner().Stop(ctx, info, expected, options)
}

type StartOptions struct {
	Args   []string
	Dir    string
	Env    []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func Start(executable string, options StartOptions) (*os.Process, error) {
	if executable == "" {
		return nil, fmt.Errorf("start process: empty executable")
	}
	command := exec.Command(executable, options.Args...)
	command.Dir = options.Dir
	if options.Env != nil {
		command.Env = append([]string(nil), options.Env...)
	}
	command.Stdin = options.Stdin
	command.Stdout = options.Stdout
	command.Stderr = options.Stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start process: %w", err)
	}
	return command.Process, nil
}
