package zcode

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCapabilitiesIncludeOnlyProvenSharedProducts(t *testing.T) {
	adapter := NewAdapter(PathsForStateDir(filepath.Join(t.TempDir(), "v2")))
	capability := adapter.Capabilities()
	if capability.StateGroup != "zcode-v2-auth" || !capability.RotatesTelemetry {
		t.Fatalf("unexpected capability: %+v", capability)
	}
	if capability.SafeCLIRestart {
		t.Fatal("CLI restart must remain unsupported")
	}
	if len(capability.Products) != 2 {
		t.Fatalf("products = %+v", capability.Products)
	}
}

func TestAbsentSharedStateLockIsSafe(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "v2")
	paths := PathsForStateDir(stateDir)
	if err := CheckSharedStateLock(paths); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.TelemetryLockPath); !os.IsNotExist(err) {
		t.Fatalf("probe created lock: %v", err)
	}
}
