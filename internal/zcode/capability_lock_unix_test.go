//go:build !windows

package zcode

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHeldSharedStateLockRefusesMutationProbe(t *testing.T) {
	stateDir := t.TempDir()
	paths := PathsForStateDir(filepath.Join(stateDir, "v2"))
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.TelemetryLockPath, []byte("owned by ZCode"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckSharedStateLock(paths); !errors.Is(err, ErrSharedStateBusy) {
		t.Fatalf("probe error = %v, want busy", err)
	}
}
