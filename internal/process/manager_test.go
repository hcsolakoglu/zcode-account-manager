package process

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagerSelectorCompatibility(t *testing.T) {
	manager := NewMultiManager("/does/not/exist/zcode", "/does/not/exist/zcode-cli")
	if len(manager.Executables) != 2 || manager.Executable != manager.Executables[0] {
		t.Fatalf("manager selectors = %+v", manager)
	}
}

func TestSelectorIdentityResolvesAliases(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "zcode")
	alias := filepath.Join(dir, "zcode-cli")
	if err := os.WriteFile(target, []byte("image"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if selectorIdentity(target) != selectorIdentity(alias) {
		t.Fatal("selectors for one executable image were not deduplicated")
	}
}

func TestClassifySharedImageFailsClosed(t *testing.T) {
	tests := map[string]string{
		"ZCode":         "desktop",
		"ZCode.exe":     "desktop",
		"zcode-cli":     "cli",
		"zcode-cli.exe": "cli",
		"zcode":         "cli",
		"":              "cli",
	}
	for name, want := range tests {
		if got := classifySharedImage(name); got != want {
			t.Errorf("classifySharedImage(%q) = %q, want %q", name, got, want)
		}
	}
}
