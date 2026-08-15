//go:build linux

// Package process provides the deliberately narrow process operations needed
// by the ZCode adapter.  Detection uses /proc/<pid>/exe and exact executable
// identity; command-line substring matching is intentionally not used, so a
// zcode-cli process cannot be mistaken for the ZCode desktop process.
package process

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	ErrProcessNotFound = errors.New("process not found")
	ErrProcessChanged  = errors.New("process identity changed")
	ErrStopTimeout     = errors.New("process did not exit before timeout")
	ErrForceRequired   = errors.New("force termination was not requested")
)

// Info is a process identity snapshot.  StartTime is read from /proc and is
// used to avoid signaling a recycled PID.  Args are intentionally omitted: a
// command line can contain tokens, so detection never reads or returns it.
type Info struct {
	PID        int
	Executable string
	Product    string
	Name       string
	UID        uint32
	StartTime  uint64
}

// Scanner reads process information from ProcRoot.  ProcRoot is configurable
// for deterministic tests; production uses /proc.
type Scanner struct {
	ProcRoot string
	SelfPID  int
}

func NewScanner() Scanner {
	return Scanner{ProcRoot: "/proc", SelfPID: os.Getpid()}
}

// List returns all processes whose resolved /proc/<pid>/exe exactly matches
// executable.  If executable has no slash, an exact basename match is used.
func List(executable string) ([]Info, error) {
	return NewScanner().List(executable)
}

func (s Scanner) List(executable string) ([]Info, error) {
	if s.ProcRoot == "" {
		s.ProcRoot = "/proc"
	}
	entries, err := os.ReadDir(s.ProcRoot)
	if err != nil {
		return nil, err
	}
	result := make([]Info, 0)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || pid == s.SelfPID {
			continue
		}
		info, ok := s.read(pid)
		if !ok {
			// A matching executable with unreadable UID/start-time metadata is
			// not proof that ZCode is stopped. Fail closed so callers never
			// mutate live state on an unverifiable process snapshot.
			actual, linkErr := os.Readlink(filepath.Join(s.ProcRoot, entry.Name(), "exe"))
			if linkErr == nil && MatchesExecutable(executable, actual) {
				return nil, fmt.Errorf("cannot verify process %d identity", pid)
			}
			continue
		}
		if info.UID != uint32(os.Geteuid()) || !MatchesExecutable(executable, info.Executable) {
			continue
		}
		result = append(result, info)
	}
	return result, nil
}

// Find is an alias for List for callers that use process-manager terminology.
func Find(executable string) ([]Info, error) {
	return List(executable)
}

// MatchesExecutable compares canonical executable paths, or exact basenames
// for a name-only selector.  It never performs prefix/substring matching.
func MatchesExecutable(expected, actual string) bool {
	if expected == "" || actual == "" {
		return false
	}
	if strings.ContainsRune(expected, filepath.Separator) {
		expectedPath, expectedErr := canonicalPath(expected)
		actualPath, actualErr := canonicalPath(actual)
		if expectedErr == nil && actualErr == nil {
			return expectedPath == actualPath
		}
		return filepath.Clean(expected) == filepath.Clean(actual)
	}
	return filepath.Base(actual) == expected
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		abs = resolved
	}
	return filepath.Clean(abs), nil
}

func (s Scanner) read(pid int) (Info, bool) {
	base := filepath.Join(s.ProcRoot, strconv.Itoa(pid))
	executable, err := os.Readlink(filepath.Join(base, "exe"))
	if err != nil {
		return Info{}, false
	}
	nameBytes, err := os.ReadFile(filepath.Join(base, "comm"))
	if err != nil {
		return Info{}, false
	}
	name := strings.TrimSpace(string(nameBytes))
	if name == "" {
		return Info{}, false
	}
	uid, ok := readUID(filepath.Join(base, "status"))
	if !ok {
		return Info{}, false
	}
	startTime, ok := readStartTime(filepath.Join(base, "stat"))
	if !ok || startTime == 0 {
		return Info{}, false
	}
	info := Info{PID: pid, Executable: executable, Name: name, UID: uid, StartTime: startTime}
	return info, true
}

func (s Scanner) readMatching(pid int, executable string) (Info, bool) {
	info, ok := s.read(pid)
	if !ok || !MatchesExecutable(executable, info.Executable) {
		return Info{}, false
	}
	return info, true
}

func readUID(path string) (uint32, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) == 0 {
			return 0, false
		}
		uid, err := strconv.ParseUint(fields[0], 10, 32)
		return uint32(uid), err == nil
	}
	return 0, false
}

func readStartTime(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	line := strings.TrimSpace(string(data))
	closeParen := strings.LastIndexByte(line, ')')
	if closeParen < 0 || closeParen+1 >= len(line) {
		return 0, false
	}
	fields := strings.Fields(line[closeParen+1:])
	// fields[0] is state (field 3); starttime is field 22.
	if len(fields) <= 19 {
		return 0, false
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	return value, err == nil
}

// IsAlive checks a snapshot's PID, executable, UID, and start time.  A missing
// start time fails closed: without it, a PID could have been recycled and the
// caller must not signal it.  Detection may still report the process, allowing
// callers to surface a safe "cannot verify"/still-running result.
func (s Scanner) IsAlive(info Info, expectedExecutable string) bool {
	current, ok := s.readMatching(info.PID, expectedExecutable)
	if !ok {
		return false
	}
	if info.StartTime == 0 || current.StartTime == 0 || info.UID != uint32(os.Geteuid()) {
		return false
	}
	if info.UID != current.UID {
		return false
	}
	if info.StartTime != current.StartTime {
		return false
	}
	return true
}

// StopOptions controls bounded graceful shutdown.  Force must be explicitly
// true before SIGKILL is considered.
type StopOptions struct {
	Timeout      time.Duration
	PollInterval time.Duration
	Force        bool
}

func normalizeStopOptions(options StopOptions) StopOptions {
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 50 * time.Millisecond
	}
	return options
}

// Stop sends SIGTERM, then waits up to Timeout.  It never escalates unless
// Force is explicitly requested.  A process snapshot is revalidated before
// each signal to avoid killing a recycled PID.
func (s Scanner) Stop(ctx context.Context, info Info, expectedExecutable string, options StopOptions) error {
	options = normalizeStopOptions(options)
	if ctx == nil {
		ctx = context.Background()
	}
	if info.PID <= 0 || info.PID == os.Getpid() {
		return ErrProcessNotFound
	}
	if !s.IsAlive(info, expectedExecutable) {
		return nil
	}
	if err := s.signal(info, expectedExecutable, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if s.waitExited(ctx, info, expectedExecutable, options.Timeout, options.PollInterval) {
		return nil
	}
	if !options.Force {
		return ErrStopTimeout
	}
	if !s.IsAlive(info, expectedExecutable) {
		return nil
	}
	if err := s.signal(info, expectedExecutable, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if s.waitExited(ctx, info, expectedExecutable, options.Timeout, options.PollInterval) {
		return nil
	}
	return ErrStopTimeout
}

func (s Scanner) signal(info Info, expectedExecutable string, signal syscall.Signal) error {
	if !s.IsAlive(info, expectedExecutable) {
		return ErrProcessChanged
	}
	return syscall.Kill(info.PID, signal)
}

func (s Scanner) waitExited(ctx context.Context, info Info, expectedExecutable string, timeout, interval time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if !s.IsAlive(info, expectedExecutable) {
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

// Stop is the package-level convenience form using /proc.
func Stop(ctx context.Context, info Info, expectedExecutable string, options StopOptions) error {
	return NewScanner().Stop(ctx, info, expectedExecutable, options)
}

// StartOptions starts an executable directly (without a shell).  Nil streams
// are inherited according to os/exec defaults, while explicit streams can be
// supplied by callers that need a supervised process.
type StartOptions struct {
	Args   []string
	Dir    string
	Env    []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Start launches executable directly and returns as soon as the child has
// started.  It performs no version probe and therefore cannot accidentally
// launch a GUI as a side effect of detection.
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
