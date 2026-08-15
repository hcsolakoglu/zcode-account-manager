package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	DataDir            string `json:"data_dir,omitempty"`
	ZCodeStateDir      string `json:"zcode_state_dir,omitempty"`
	ZCodeExecutable    string `json:"zcode_executable,omitempty"`
	ZCodeCLIExecutable string `json:"zcode_cli_executable,omitempty"`
	BackupLimit        int    `json:"backup_limit,omitempty"`
	StopTimeoutSec     int    `json:"stop_timeout_seconds,omitempty"`
	LoginTimeoutSec    int    `json:"login_timeout_seconds,omitempty"`
}

func Defaults() (Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, fmt.Errorf("resolve home directory: %w", err)
	}
	dataHome := defaultDataBase(home)
	return Config{
		DataDir:            filepath.Join(dataHome, "zcode-auth"),
		ZCodeStateDir:      defaultStateDir(home),
		ZCodeExecutable:    defaultDesktopExecutable(home),
		ZCodeCLIExecutable: defaultCLIExecutable(home),
		BackupLimit:        10,
		StopTimeoutSec:     10,
		LoginTimeoutSec:    300,
	}, nil
}

func ConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = defaultConfigBase(home)
	}
	if !filepath.IsAbs(base) {
		return "", fmt.Errorf("configuration base must be an absolute path")
	}
	return filepath.Join(base, "zcode-auth", "config.json"), nil
}

// Load merges an optional config file over secure defaults. Environment
// overrides exist for packaging and isolated integration tests; none carry
// secret material.
func Load() (Config, error) {
	cfg, err := Defaults()
	if err != nil {
		return Config{}, err
	}
	path, err := ConfigPath()
	if err != nil {
		return Config{}, err
	}
	if err := validateConfigParent(filepath.Dir(path)); err != nil {
		return Config{}, fmt.Errorf("inspect configuration path: %w", err)
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return Config{}, fmt.Errorf("configuration path is not a regular file: %s", path)
		}
		if !configFileOwnerSafe(path, info) || !configPermissionsSafe(path, info) {
			return Config{}, fmt.Errorf("configuration path has unsafe ownership or permissions: %s", path)
		}
		data, readErr := readConfigFile(path)
		if readErr != nil {
			return Config{}, fmt.Errorf("read configuration: %w", readErr)
		}
		if decodeErr := decodeConfig(data, &cfg); decodeErr != nil {
			return Config{}, fmt.Errorf("parse configuration: %w", decodeErr)
		}
	} else if !os.IsNotExist(statErr) {
		return Config{}, fmt.Errorf("inspect configuration: %w", statErr)
	}
	applyString := func(name string, target *string) {
		if value := os.Getenv(name); value != "" {
			*target = value
		}
	}
	applyInt := func(name string, target *int) error {
		value := os.Getenv(name)
		if value == "" {
			return nil
		}
		parsed, parseErr := strconv.Atoi(value)
		if parseErr != nil || parsed <= 0 {
			return fmt.Errorf("%s must be a positive integer", name)
		}
		*target = parsed
		return nil
	}
	applyString("ZCODE_AUTH_DATA_DIR", &cfg.DataDir)
	applyString("ZCODE_AUTH_ZCODE_STATE_DIR", &cfg.ZCodeStateDir)
	applyString("ZCODE_AUTH_ZCODE_EXECUTABLE", &cfg.ZCodeExecutable)
	applyString("ZCODE_AUTH_ZCODE_CLI_EXECUTABLE", &cfg.ZCodeCLIExecutable)
	if err := applyInt("ZCODE_AUTH_BACKUP_LIMIT", &cfg.BackupLimit); err != nil {
		return Config{}, err
	}
	if err := applyInt("ZCODE_AUTH_STOP_TIMEOUT", &cfg.StopTimeoutSec); err != nil {
		return Config{}, err
	}
	if err := applyInt("ZCODE_AUTH_LOGIN_TIMEOUT", &cfg.LoginTimeoutSec); err != nil {
		return Config{}, err
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validateConfigParent(path string) error {
	clean := filepath.Clean(path)
	var chain []string
	for current := clean; ; current = filepath.Dir(current) {
		chain = append(chain, current)
		if parent := filepath.Dir(current); parent == current {
			break
		}
	}
	for index := len(chain) - 1; index >= 0; index-- {
		info, err := os.Lstat(chain[index])
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("unsafe directory component %s", chain[index])
		}
		if err := configDirectorySafe(chain[index]); err != nil {
			return err
		}
	}
	return nil
}

func Validate(cfg Config) error {
	if cfg.DataDir == "" || cfg.ZCodeStateDir == "" || cfg.ZCodeExecutable == "" {
		return fmt.Errorf("data_dir, zcode_state_dir, and zcode_executable must be set")
	}
	for name, path := range map[string]string{
		"data_dir": cfg.DataDir, "zcode_state_dir": cfg.ZCodeStateDir, "zcode_executable": cfg.ZCodeExecutable,
	} {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	if cfg.ZCodeCLIExecutable != "" && !filepath.IsAbs(cfg.ZCodeCLIExecutable) {
		return fmt.Errorf("zcode_cli_executable must be an absolute path")
	}
	data := filepath.Clean(cfg.DataDir)
	state := filepath.Clean(cfg.ZCodeStateDir)
	if data == state || pathWithin(data, state) || pathWithin(state, data) {
		return fmt.Errorf("data_dir and zcode_state_dir must not overlap")
	}
	if cfg.BackupLimit <= 0 || cfg.StopTimeoutSec <= 0 || cfg.LoginTimeoutSec <= 0 {
		return fmt.Errorf("backup and timeout settings must be positive")
	}
	return nil
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && relative != "." && !filepath.IsAbs(relative) && !stringsHasParent(relative)
}

func stringsHasParent(relative string) bool {
	return relative == ".." || len(relative) > 3 && relative[:3] == ".."+string(filepath.Separator)
}

func decodeConfig(data []byte, cfg *Config) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("configuration must be a JSON object")
	}
	seen := make(map[string]struct{})
	allowed := map[string]struct{}{
		"data_dir": {}, "zcode_state_dir": {}, "zcode_executable": {}, "zcode_cli_executable": {},
		"backup_limit": {}, "stop_timeout_seconds": {}, "login_timeout_seconds": {},
	}
	// Validate top-level uniqueness before the typed decode. Configuration has
	// no nested object fields, so this completely covers duplicate keys.
	probe := json.NewDecoder(bytes.NewReader(data))
	if _, err := probe.Token(); err != nil {
		return err
	}
	for probe.More() {
		keyToken, err := probe.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("invalid configuration key")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate configuration key %q", key)
		}
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown configuration key %q", key)
		}
		seen[key] = struct{}{}
		var discard any
		if err := probe.Decode(&discard); err != nil {
			return err
		}
	}
	if _, err := probe.Token(); err != nil {
		return err
	}
	if _, err := probe.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing configuration data")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(cfg); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing configuration data")
	}
	return nil
}
