//go:build windows

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
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ErrProcessNotFound     = errors.New("process not found")
	ErrProcessChanged      = errors.New("process identity changed")
	ErrStopTimeout         = errors.New("process did not exit before timeout")
	ErrForceRequired       = errors.New("force termination was not requested")
	ErrGracefulUnsupported = errors.New("safe graceful shutdown is unavailable on this Windows process")
)

type Info struct {
	PID        int
	Executable string
	Product    string
	Name       string
	UID        uint32
	StartTime  uint64
	Identity   string
}

type Scanner struct {
	ProcRoot string
	SelfPID  int
}

func NewScanner() Scanner                    { return Scanner{SelfPID: os.Getpid()} }
func List(executable string) ([]Info, error) { return NewScanner().List(executable) }
func Find(executable string) ([]Info, error) { return List(executable) }

func (s Scanner) List(executable string) ([]Info, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	result := make([]Info, 0)
	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		pid := int(entry.ProcessID)
		if pid > 0 && pid != s.SelfPID {
			name := windows.UTF16ToString(entry.ExeFile[:])
			if info, ok := windowsSnapshot(pid, executable); ok {
				info.Name = name
				result = append(result, info)
			} else if strings.EqualFold(filepath.Base(executable), filepath.Base(windows.UTF16ToString(entry.ExeFile[:]))) {
				// The Toolhelp record identifies a process with the same image
				// basename, but restricted process handles prevented verifying
				// its full path/owner/start time. Treat that as an owner we
				// cannot safely classify instead of assuming ZCode is stopped.
				return nil, fmt.Errorf("cannot verify process %d identity", pid)
			}
		}
		err = windows.Process32Next(snapshot, &entry)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	return result, nil
}

func windowsSnapshot(pid int, expected string) (Info, bool) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return Info{}, false
	}
	defer windows.CloseHandle(handle)
	path, err := queryImagePath(handle)
	if err != nil || !MatchesExecutable(expected, path) {
		return Info{}, false
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return Info{}, false
	}
	start := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	if start == 0 {
		return Info{}, false
	}
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return Info{}, false
	}
	defer token.Close()
	userInfo, err := token.GetTokenUser()
	if err != nil || userInfo == nil || userInfo.User.Sid == nil {
		return Info{}, false
	}
	return Info{PID: pid, Executable: path, StartTime: start, Identity: userInfo.User.Sid.String()}, true
}

func queryImagePath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_PATH)
	for {
		size := uint32(len(buffer))
		if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err == nil {
			return filepath.Clean(windows.UTF16ToString(buffer[:size])), nil
		} else if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			buffer = make([]uint16, len(buffer)*2)
			if len(buffer) > 32768 {
				return "", err
			}
		} else {
			return "", err
		}
	}
}

func MatchesExecutable(expected, actual string) bool {
	if expected == "" || actual == "" {
		return false
	}
	if strings.ContainsRune(expected, filepath.Separator) {
		expectedPath, e1 := canonicalPath(expected)
		actualPath, e2 := canonicalPath(actual)
		return e1 == nil && e2 == nil && strings.EqualFold(expectedPath, actualPath)
	}
	return strings.EqualFold(filepath.Base(actual), expected)
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

func currentWindowsIdentity() string {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return ""
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return ""
	}
	return user.User.Sid.String()
}

func (s Scanner) IsAlive(info Info, expected string) bool {
	current, ok := windowsSnapshot(info.PID, expected)
	return ok && current.StartTime == info.StartTime && current.Identity == info.Identity && current.Identity != "" && current.Identity == currentWindowsIdentity()
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
func (s Scanner) Stop(context.Context, Info, string, StopOptions) error {
	// Sending a guessed console event or WM_CLOSE can target the wrong GUI
	// window. Refuse restart unless a future Windows supervisor adds a verified
	// process-specific graceful-shutdown protocol.
	return ErrGracefulUnsupported
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
