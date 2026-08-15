package process

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestMatchesExecutableUsesExactIdentity(t *testing.T) {
	if !MatchesExecutable("/usr/bin/zcode", "/usr/bin/zcode") {
		t.Fatal("exact executable did not match")
	}
	if MatchesExecutable("/usr/bin/zcode", "/usr/bin/zcode-cli") {
		t.Fatal("zcode-cli must not match zcode")
	}
	if MatchesExecutable("zcode", "/usr/bin/zcode-cli") {
		t.Fatal("basename prefix must not match")
	}
	if !MatchesExecutable("zcode", "/opt/ZCode/zcode") {
		t.Fatal("exact basename did not match")
	}
}

func TestVersionReadsStaticPackageWithoutLaunching(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "zcode")
	if err := os.WriteFile(executable, []byte("not executable for metadata test"), 0o700); err != nil {
		t.Fatal(err)
	}
	resources := filepath.Join(dir, "resources")
	if err := os.Mkdir(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "package.json"), []byte(`{"version":"3.7.7"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	version, err := Version(executable)
	if err != nil || version != "3.7.7" {
		t.Fatalf("version=%q err=%v", version, err)
	}
}

func TestDetectVersionDoesNotExecuteByDefault(t *testing.T) {
	version, err := DetectVersion(context.Background(), filepath.Join(t.TempDir(), "missing"), VersionOptions{})
	if version != "" || !errors.Is(err, ErrVersionUnavailable) {
		t.Fatalf("version=%q err=%v", version, err)
	}
}

func TestStopRequiresExplicitForce(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "trap '' TERM; sleep 10")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _, _ = command.Process.Wait() }()

	scanner := NewScanner()
	var info Info
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		matches, err := scanner.List("/bin/sh")
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range matches {
			if candidate.PID == command.Process.Pid {
				info = candidate
			}
		}
		if info.PID != 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if info.PID == 0 {
		t.Fatal("started process was not detected")
	}
	if err := scanner.Stop(context.Background(), info, "/bin/sh", StopOptions{Timeout: 20 * time.Millisecond, PollInterval: 5 * time.Millisecond}); !errors.Is(err, ErrStopTimeout) {
		t.Fatalf("non-force stop error = %v", err)
	}
	if err := scanner.Stop(context.Background(), info, "/bin/sh", StopOptions{Timeout: time.Second, PollInterval: 5 * time.Millisecond, Force: true}); err != nil {
		t.Fatalf("force stop error = %v", err)
	}
}

func TestStopFailsClosedWhenStartTimeCannotBeVerified(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "1234")
	if err := os.Mkdir(procDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/sh", filepath.Join(procDir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "status"), []byte("Name:\tsh\nUid:\t1000\t1000\t1000\t1000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A malformed stat file makes the PID identity unverifiable.  The
	// scanner must omit the process because it cannot establish a safe identity.
	if err := os.WriteFile(filepath.Join(procDir, "stat"), []byte("malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := Scanner{ProcRoot: root, SelfPID: os.Getpid()}
	items, err := scanner.List("/bin/sh")
	if err == nil || len(items) != 0 {
		t.Fatalf("List items=%+v err=%v, want fail-closed error", items, err)
	}
}
