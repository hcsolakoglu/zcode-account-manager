package transaction

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hcsolakoglu/zcode-account-manager/internal/model"
)

// BackupKind distinguishes automatic rollback snapshots from user-requested
// manual backups.  Automatic rotation only removes Automatic files; manual
// backups are never silently discarded by the automatic retention policy.
type BackupKind string

const (
	Automatic BackupKind = "automatic"
	Manual    BackupKind = "manual"
)

// EncryptedSessionBundle is the only payload accepted by BackupStore.  The
// byte slices must already be authenticated-encrypted by the profile layer.
// Presence is explicit so nil telemetry means "remove telemetry" while a
// non-nil empty encrypted document remains a present document.
type EncryptedSessionBundle struct {
	Credentials        []byte `json:"credentials,omitempty"`
	Telemetry          []byte `json:"telemetry,omitempty"`
	CredentialsPresent bool   `json:"credentials_present"`
	TelemetryPresent   bool   `json:"telemetry_present"`
}

// BackupRequest describes one snapshot.  Metadata contains no credential
// bytes.  Payload must be encrypted before passing it to this package.
type BackupRequest struct {
	Metadata model.BackupMetadata
	Payload  EncryptedSessionBundle
	Kind     BackupKind
	// Manual is a convenience alias for Kind: Manual.  It is useful for CLI
	// callers and does not change the retention rules for an explicit Kind.
	Manual bool
}

// BackupStoreOptions configures retention, locking, and failure injection.
type BackupStoreOptions struct {
	AutomaticLimit int
	// Limit is an alias for AutomaticLimit.  The default is ten automatic
	// backups; zero and negative values also use that safe default.
	Limit           int
	LockPath        string
	FailureInjector FailureInjector
}

// BackupStore writes encrypted snapshot records below Dir with 0600 files and
// a 0700 directory.
type BackupStore struct {
	dir      string
	limit    int
	lockPath string
	injector FailureInjector
}

// NewBackupStore validates (and, when absent, creates) a private backup
// directory.  Construction itself does not write any backup payload.
func NewBackupStore(dir string, options BackupStoreOptions) (*BackupStore, error) {
	dir, err := absolutePath(dir)
	if err != nil {
		return nil, fmt.Errorf("backup directory: %w", err)
	}
	if err := validateParentDirectory(filepath.Dir(dir)); err != nil {
		return nil, fmt.Errorf("backup parent: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create backup directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat backup directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("backup path %q is not a directory", dir)
	}
	if err := checkOwner(info, dir); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod backup directory: %w", err)
	}
	if err := hardenSensitiveDirectory(dir); err != nil {
		return nil, fmt.Errorf("secure backup directory: %w", err)
	}
	limit := options.AutomaticLimit
	if limit == 0 {
		limit = options.Limit
	}
	if limit <= 0 {
		limit = 10
	}
	lockPath := options.LockPath
	if lockPath != "" {
		lockPath, err = absolutePath(lockPath)
		if err != nil {
			return nil, fmt.Errorf("backup lock path: %w", err)
		}
	}
	return &BackupStore{dir: dir, limit: limit, lockPath: lockPath, injector: options.FailureInjector}, nil
}

// Dir returns the normalized backup directory.
func (s *BackupStore) Dir() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// Create persists an encrypted backup and rotates only automatic snapshots.
func (s *BackupStore) Create(request BackupRequest) (BackupInfo, error) {
	if s == nil {
		return BackupInfo{}, errors.New("nil backup store")
	}
	unlock, err := s.acquire()
	if err != nil {
		return BackupInfo{}, err
	}
	if unlock != nil {
		defer func() { _ = unlock.Close() }()
	}
	return s.createLocked(request)
}

// CreateAutomatic creates an automatic snapshot.
func (s *BackupStore) CreateAutomatic(metadata model.BackupMetadata, payload EncryptedSessionBundle) (BackupInfo, error) {
	return s.Create(BackupRequest{Metadata: metadata, Payload: payload, Kind: Automatic})
}

// CreateManual creates a manual snapshot that automatic rotation will retain.
func (s *BackupStore) CreateManual(metadata model.BackupMetadata, payload EncryptedSessionBundle) (BackupInfo, error) {
	return s.Create(BackupRequest{Metadata: metadata, Payload: payload, Kind: Manual, Manual: true})
}

func (s *BackupStore) acquire() (*Lock, error) {
	if s.lockPath == "" {
		return nil, nil
	}
	lock, err := AcquireExclusive(s.lockPath)
	if err != nil {
		return nil, fmt.Errorf("acquire backup lock: %w", err)
	}
	return lock, nil
}

func (s *BackupStore) createLocked(request BackupRequest) (BackupInfo, error) {
	kind := request.Kind
	if request.Manual {
		kind = Manual
	}
	if kind == "" {
		kind = Automatic
	}
	if kind != Automatic && kind != Manual {
		return BackupInfo{}, fmt.Errorf("invalid backup kind %q", kind)
	}
	payload, err := normalizeEncryptedPayload(request.Payload)
	if err != nil {
		return BackupInfo{}, err
	}
	metadata := request.Metadata
	if metadata.SchemaVersion == 0 {
		metadata.SchemaVersion = model.SchemaVersion
	}
	adapter, adapterErr := model.NormalizeAdapterMetadata(metadata.Adapter)
	if adapterErr != nil {
		return BackupInfo{}, adapterErr
	}
	metadata.Adapter = adapter
	if metadata.SchemaVersion != model.SchemaVersion {
		return BackupInfo{}, fmt.Errorf("unsupported backup metadata schema %d", metadata.SchemaVersion)
	}
	if metadata.ID == "" {
		metadata.ID = newIdentifier()
	}
	if !validIdentifier(metadata.ID) {
		return BackupInfo{}, fmt.Errorf("invalid backup id %q", metadata.ID)
	}
	if metadata.CreatedAt.IsZero() {
		metadata.CreatedAt = time.Now().UTC()
	}
	metadata.CreatedAt = metadata.CreatedAt.UTC()
	if metadata.Reason == "" {
		metadata.Reason = "automatic rollback snapshot"
		if kind == Manual {
			metadata.Reason = "manual snapshot"
		}
	}
	metadata.CredentialsSHA = payloadChecksum(payload.Credentials, payload.CredentialsPresent)
	metadata.TelemetrySHA = payloadChecksum(payload.Telemetry, payload.TelemetryPresent)
	record := backupRecord{
		SchemaVersion:  model.SchemaVersion,
		Kind:           kind,
		Metadata:       metadata,
		Payload:        payload,
		CredentialsSHA: metadata.CredentialsSHA,
		TelemetrySHA:   metadata.TelemetrySHA,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return BackupInfo{}, fmt.Errorf("marshal backup: %w", err)
	}
	path := s.pathFor(kind, metadata.ID)
	if _, err := validateTarget(path); err != nil {
		return BackupInfo{}, err
	}
	if _, err := os.Lstat(path); err == nil {
		return BackupInfo{}, fmt.Errorf("backup %q already exists", metadata.ID)
	} else if !os.IsNotExist(err) {
		return BackupInfo{}, fmt.Errorf("check backup path: %w", err)
	}
	if err := atomicWrite(path, encoded, 0o600, s.injector, "backup"); err != nil {
		return BackupInfo{}, fmt.Errorf("write backup: %w", err)
	}
	if err := invoke(s.injector, StageAfterBackupWrite, path); err != nil {
		return BackupInfo{}, err
	}
	if kind == Automatic {
		if err := s.rotateAutomatic(); err != nil {
			return BackupInfo{}, fmt.Errorf("rotate automatic backups: %w", err)
		}
	}
	return backupInfoFromRecord(path, record), nil
}

// List returns valid backups newest first.  It does not include temporary
// files, malformed records, or symlink entries; malformed/symlink entries are
// reported as errors so they are never silently mistaken for valid snapshots.
func (s *BackupStore) List() ([]BackupInfo, error) {
	if s == nil {
		return nil, errors.New("nil backup store")
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("list backups: %w", err)
	}
	backups := make([]BackupInfo, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || (!strings.HasPrefix(name, "automatic-") && !strings.HasPrefix(name, "manual-")) {
			continue
		}
		path := filepath.Join(s.dir, name)
		record, err := s.readRecord(path)
		if err != nil {
			return nil, err
		}
		backups = append(backups, backupInfoFromRecord(path, record))
	}
	sort.Slice(backups, func(i, j int) bool {
		if backups[i].Metadata.CreatedAt.Equal(backups[j].Metadata.CreatedAt) {
			return backups[i].ID > backups[j].ID
		}
		return backups[i].Metadata.CreatedAt.After(backups[j].Metadata.CreatedAt)
	})
	return backups, nil
}

// RestoredBackup is validated encrypted payload plus metadata.  The caller
// must decrypt/authenticate Payload before using it to update live state.
type RestoredBackup struct {
	ID       string
	Path     string
	Kind     BackupKind
	Metadata model.BackupMetadata
	Payload  EncryptedSessionBundle
}

// Restore validates and returns an encrypted backup.  It does not modify live
// credentials; the transaction Engine is responsible for applying a caller-
// decrypted SessionBundle.
func (s *BackupStore) Restore(id string) (RestoredBackup, error) {
	if s == nil {
		return RestoredBackup{}, errors.New("nil backup store")
	}
	if !validIdentifier(id) {
		return RestoredBackup{}, fmt.Errorf("invalid backup id %q", id)
	}
	var found string
	for _, kind := range []BackupKind{Automatic, Manual} {
		path := s.pathFor(kind, id)
		if _, err := os.Lstat(path); err == nil {
			if found != "" {
				return RestoredBackup{}, fmt.Errorf("backup id %q is ambiguous", id)
			}
			found = path
		} else if !os.IsNotExist(err) {
			return RestoredBackup{}, fmt.Errorf("check backup %q: %w", id, err)
		}
	}
	if found == "" {
		return RestoredBackup{}, fmt.Errorf("backup %q not found", id)
	}
	record, err := s.readRecord(found)
	if err != nil {
		return RestoredBackup{}, err
	}
	return RestoredBackup{
		ID:       record.Metadata.ID,
		Path:     found,
		Kind:     record.Kind,
		Metadata: record.Metadata,
		Payload:  record.Payload,
	}, nil
}

func (s *BackupStore) rotateAutomatic() error {
	if err := invoke(s.injector, StageBeforeBackupRotate, s.dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	automatic := make([]BackupInfo, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "automatic-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		record, err := s.readRecord(path)
		if err != nil {
			return err
		}
		if record.Kind != Automatic {
			return fmt.Errorf("automatic filename contains %s record", record.Kind)
		}
		automatic = append(automatic, backupInfoFromRecord(path, record))
	}
	sort.Slice(automatic, func(i, j int) bool {
		if automatic[i].Metadata.CreatedAt.Equal(automatic[j].Metadata.CreatedAt) {
			return automatic[i].ID > automatic[j].ID
		}
		return automatic[i].Metadata.CreatedAt.After(automatic[j].Metadata.CreatedAt)
	})
	if len(automatic) <= s.limit {
		return invoke(s.injector, StageAfterBackupRotate, s.dir)
	}
	for _, old := range automatic[s.limit:] {
		if err := secureRemove(old.Path, nil, StageAfterBackupRotate); err != nil {
			return err
		}
	}
	return invoke(s.injector, StageAfterBackupRotate, s.dir)
}

func (s *BackupStore) readRecord(path string) (backupRecord, error) {
	info, err := validateTarget(path)
	if err != nil {
		return backupRecord{}, err
	}
	if info == nil {
		return backupRecord{}, fmt.Errorf("backup %q not found", path)
	}
	if !privateFilePermissions(path, info) {
		return backupRecord{}, fmt.Errorf("backup %q has insecure permissions %04o", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return backupRecord{}, fmt.Errorf("read backup %q: %w", path, err)
	}
	var record backupRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return backupRecord{}, fmt.Errorf("invalid backup %q: %w", path, err)
	}
	if err := validateBackupRecord(record); err != nil {
		return backupRecord{}, fmt.Errorf("validate backup %q: %w", path, err)
	}
	name := filepath.Base(path)
	var expectedKind BackupKind
	switch {
	case strings.HasPrefix(name, string(Automatic)+"-"):
		expectedKind = Automatic
	case strings.HasPrefix(name, string(Manual)+"-"):
		expectedKind = Manual
	default:
		return backupRecord{}, fmt.Errorf("backup %q has an invalid filename", path)
	}
	expectedID := strings.TrimSuffix(strings.TrimPrefix(name, string(expectedKind)+"-"), ".json")
	if record.Kind != expectedKind || record.Metadata.ID != expectedID {
		return backupRecord{}, fmt.Errorf("backup filename and metadata disagree")
	}
	return record, nil
}

func validateBackupRecord(record backupRecord) error {
	if record.SchemaVersion != model.SchemaVersion || record.Metadata.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("unsupported schema")
	}
	if record.Kind != Automatic && record.Kind != Manual {
		return fmt.Errorf("invalid kind %q", record.Kind)
	}
	adapter, err := model.NormalizeAdapterMetadata(record.Metadata.Adapter)
	if err != nil || adapter.StateGroup != model.StateGroupID {
		return fmt.Errorf("unsupported adapter metadata")
	}
	if !validIdentifier(record.Metadata.ID) {
		return fmt.Errorf("invalid id")
	}
	if record.Metadata.CreatedAt.IsZero() {
		return fmt.Errorf("missing created_at")
	}
	payload, err := normalizeEncryptedPayload(record.Payload)
	if err != nil {
		return err
	}
	if record.CredentialsSHA != payloadChecksum(payload.Credentials, payload.CredentialsPresent) {
		return fmt.Errorf("credentials checksum mismatch")
	}
	if record.TelemetrySHA != payloadChecksum(payload.Telemetry, payload.TelemetryPresent) {
		return fmt.Errorf("telemetry checksum mismatch")
	}
	if record.Metadata.CredentialsSHA != record.CredentialsSHA || record.Metadata.TelemetrySHA != record.TelemetrySHA {
		return fmt.Errorf("metadata checksum mismatch")
	}
	return nil
}

func normalizeEncryptedPayload(payload EncryptedSessionBundle) (EncryptedSessionBundle, error) {
	// Non-nil bytes are a useful compatibility shorthand for callers that do
	// not need to represent an encrypted empty document.  Explicit presence
	// still wins, allowing nil/empty to remain meaningful.
	if !payload.CredentialsPresent && payload.Credentials != nil {
		payload.CredentialsPresent = true
	}
	if !payload.TelemetryPresent && payload.Telemetry != nil {
		payload.TelemetryPresent = true
	}
	if !payload.CredentialsPresent {
		payload.Credentials = nil
	}
	if !payload.TelemetryPresent {
		payload.Telemetry = nil
	}
	return payload, nil
}

func payloadChecksum(payload []byte, present bool) string {
	if !present {
		return ""
	}
	return checksum(payload)
}

func validIdentifier(id string) bool {
	if id == "" || len(id) > 160 {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func (s *BackupStore) pathFor(kind BackupKind, id string) string {
	return filepath.Join(s.dir, fmt.Sprintf("%s-%s.json", kind, id))
}

// BackupInfo is metadata about a persisted record and never contains
// decrypted credential bytes.
type BackupInfo struct {
	ID       string
	Path     string
	Kind     BackupKind
	Metadata model.BackupMetadata
}

type backupRecord struct {
	SchemaVersion  int                    `json:"schema_version"`
	Kind           BackupKind             `json:"kind"`
	Metadata       model.BackupMetadata   `json:"metadata"`
	Payload        EncryptedSessionBundle `json:"payload"`
	CredentialsSHA string                 `json:"credentials_sha256,omitempty"`
	TelemetrySHA   string                 `json:"telemetry_sha256,omitempty"`
}

func backupInfoFromRecord(path string, record backupRecord) BackupInfo {
	return BackupInfo{ID: record.Metadata.ID, Path: path, Kind: record.Kind, Metadata: record.Metadata}
}
