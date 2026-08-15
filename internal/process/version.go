package process

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrVersionUnavailable = errors.New("process version is unavailable without launching it")

// VersionOptions controls the optional fallback command.  Static metadata is
// always tried first.  AllowExecute must be explicitly enabled because an
// Electron desktop executable may open a GUI when --version is unsupported.
type VersionOptions struct {
	AllowExecute bool
	Timeout      time.Duration
}

var versionPattern = regexp.MustCompile(`\b[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\b`)

// Version reads adjacent package metadata or an Electron ASAR package header;
// it never launches executable.  ErrVersionUnavailable is expected when no
// static metadata is available.
func Version(executable string) (string, error) {
	if executable == "" {
		return "", ErrVersionUnavailable
	}
	executablePath, err := filepath.Abs(executable)
	if err != nil {
		return "", ErrVersionUnavailable
	}
	dir := filepath.Dir(executablePath)
	for _, candidate := range []string{
		filepath.Join(dir, "package.json"),
		filepath.Join(dir, "resources", "package.json"),
		filepath.Join(dir, "resources", "app", "package.json"),
		filepath.Join(filepath.Dir(dir), "resources", "package.json"),
		filepath.Join(filepath.Dir(dir), "resources", "app", "package.json"),
	} {
		if version, ok := readPackageVersion(candidate); ok {
			return version, nil
		}
	}
	for _, candidate := range []string{
		filepath.Join(dir, "resources", "app.asar"),
		filepath.Join(filepath.Dir(dir), "resources", "app.asar"),
	} {
		if version, ok := readASARVersion(candidate); ok {
			return version, nil
		}
	}
	return "", ErrVersionUnavailable
}

// DetectVersion first performs safe static detection.  Only when AllowExecute
// is true does it invoke executable --version with a bounded context.
func DetectVersion(ctx context.Context, executable string, options VersionOptions) (string, error) {
	if version, err := Version(executable); err == nil {
		return version, nil
	}
	if !options.AllowExecute {
		return "", ErrVersionUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Timeout <= 0 {
		options.Timeout = 2 * time.Second
	}
	commandCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, executable, "--version")
	var output bytes.Buffer
	command.Stdout = &limitedWriter{Writer: &output, Limit: 64 << 10}
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return "", ErrVersionUnavailable
	}
	match := versionPattern.FindString(output.String())
	if match == "" {
		return "", ErrVersionUnavailable
	}
	return match, nil
}

type limitedWriter struct {
	io.Writer
	Limit int64
	count int64
}

func (w *limitedWriter) Write(data []byte) (int, error) {
	if w.count >= w.Limit {
		return len(data), nil
	}
	remaining := w.Limit - w.count
	if int64(len(data)) > remaining {
		data = data[:remaining]
	}
	n, err := w.Writer.Write(data)
	w.count += int64(n)
	return len(data), err
}

func readPackageVersion(path string) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	var packageJSON struct {
		Version string `json:"version"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	if err := decoder.Decode(&packageJSON); err != nil {
		return "", false
	}
	version := strings.TrimSpace(packageJSON.Version)
	if version == "" || strings.ContainsAny(version, "\r\n\x00") {
		return "", false
	}
	return version, true
}

type asarEntry struct {
	Files  map[string]json.RawMessage `json:"files"`
	Size   int64                      `json:"size"`
	Offset string                     `json:"offset"`
}

func readASARVersion(path string) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	var header [16]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return "", false
	}
	headerSize := int64(binary.LittleEndian.Uint32(header[4:8]))
	jsonSize := int64(binary.LittleEndian.Uint32(header[8:12]))
	if headerSize <= 0 || jsonSize <= 0 || jsonSize > 64<<20 || headerSize > 64<<20 {
		return "", false
	}
	metadata := make([]byte, jsonSize)
	if _, err := io.ReadFull(file, metadata); err != nil {
		return "", false
	}
	var root asarEntry
	if err := json.Unmarshal(metadata, &root); err != nil {
		return "", false
	}
	entry, ok := findRootPackage(root.Files)
	if !ok || entry.Size <= 0 || entry.Size > 1<<20 {
		return "", false
	}
	offset, err := strconv.ParseInt(entry.Offset, 10, 64)
	if err != nil || offset < 0 {
		return "", false
	}
	// ASAR content begins after the 8-byte pickle prefix plus headerSize.
	contentOffset := int64(8) + headerSize + offset
	if _, err := file.Seek(contentOffset, io.SeekStart); err != nil {
		return "", false
	}
	content := make([]byte, entry.Size)
	if _, err := io.ReadFull(file, content); err != nil {
		return "", false
	}
	var packageJSON struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(content, &packageJSON); err != nil {
		return "", false
	}
	version := strings.TrimSpace(packageJSON.Version)
	return version, version != ""
}

func findRootPackage(files map[string]json.RawMessage) (asarEntry, bool) {
	if raw, ok := files["package.json"]; ok {
		var entry asarEntry
		if err := json.Unmarshal(raw, &entry); err == nil && entry.Size > 0 && entry.Offset != "" {
			return entry, true
		}
	}
	return asarEntry{}, false
}
