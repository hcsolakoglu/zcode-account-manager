package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEnvironmentOverrides(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", filepath.Join(t.TempDir(), "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "config"))
	t.Setenv("ZCODE_AUTH_DATA_DIR", "/tmp/zcode-auth-test-data")
	t.Setenv("ZCODE_AUTH_BACKUP_LIMIT", "7")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "/tmp/zcode-auth-test-data" || cfg.BackupLimit != 7 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestDefaultsHonorSharedZCodeDataBase(t *testing.T) {
	home := t.TempDir()
	base := filepath.Join(t.TempDir(), "zcode-data")
	t.Setenv("HOME", home)
	t.Setenv("ZCODE_DATA_BASE_DIR", base)
	t.Setenv("XDG_DATA_HOME", filepath.Join(t.TempDir(), "data"))
	cfg, err := Defaults()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ZCodeStateDir != filepath.Join(base, "v2") {
		t.Fatalf("state dir = %q, want shared base/v2", cfg.ZCodeStateDir)
	}
	if cfg.ZCodeCLIExecutable == "" {
		t.Fatal("bundled CLI selector is empty")
	}
}

func TestValidateRejectsRelativeAndOverlappingPaths(t *testing.T) {
	base := Config{DataDir: "/tmp/data", ZCodeStateDir: "/tmp/state", ZCodeExecutable: "/bin/true", BackupLimit: 1, StopTimeoutSec: 1, LoginTimeoutSec: 1}
	for name, mutate := range map[string]func(*Config){
		"relative": func(cfg *Config) { cfg.DataDir = "relative" },
		"equal":    func(cfg *Config) { cfg.ZCodeStateDir = cfg.DataDir },
		"nested":   func(cfg *Config) { cfg.ZCodeStateDir = filepath.Join(cfg.DataDir, "state") },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if err := Validate(cfg); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

func TestLoadRejectsDuplicateAndUnknownConfigKeys(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate": `{"backup_limit":1,"backup_limit":2}`,
		"unknown":   `{"surprise":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			configHome := filepath.Join(home, "config")
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", configHome)
			path := filepath.Join(configHome, "zcode-auth", "config.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(); err == nil || (!strings.Contains(err.Error(), "duplicate") && !strings.Contains(err.Error(), "unknown")) {
				t.Fatalf("Load error = %v", err)
			}
		})
	}
}

func TestLoadRejectsSymlinkConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	configHome := filepath.Join(home, "config")
	t.Setenv("XDG_CONFIG_HOME", configHome)
	path := filepath.Join(configHome, "zcode-auth", "config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "target")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected symlink rejection")
	}
}
