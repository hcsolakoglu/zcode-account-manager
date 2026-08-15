package commands

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hcsolakoglu/zcode-account-manager/internal/model"
	"github.com/hcsolakoglu/zcode-account-manager/internal/profile"
	"github.com/hcsolakoglu/zcode-account-manager/internal/zcode"
)

const coordinatorSchema = 1

type coordinatorRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Operation     string `json:"operation"`
	Phase         string `json:"phase"`
	OldActive     string `json:"old_active,omitempty"`
	OldPrevious   string `json:"old_previous,omitempty"`
	NewActive     string `json:"new_active,omitempty"`
	NewPrevious   string `json:"new_previous,omitempty"`
	BackupID      string `json:"backup_id,omitempty"`
	CreatedTarget bool   `json:"created_target,omitempty"`
	// TargetStateRecorded lets recovery compare the exact bytes that the
	// operation intended to install.  Older journals do not have this marker;
	// recovery retains the identity/presence fallback for those records.
	TargetStateRecorded      bool   `json:"target_state_recorded,omitempty"`
	TargetCredentialsPresent bool   `json:"target_credentials_present,omitempty"`
	TargetTelemetryPresent   bool   `json:"target_telemetry_present,omitempty"`
	TargetCredentialsSHA     string `json:"target_credentials_sha256,omitempty"`
	TargetTelemetrySHA       string `json:"target_telemetry_sha256,omitempty"`
}

func (a *App) coordinatorPath() string {
	return filepath.Join(a.Config.DataDir, "coordinator.journal")
}

func (a *App) beginCoordinator(operation, newActive, backupID string) (coordinatorRecord, error) {
	registry, err := a.Store.Registry()
	if err != nil {
		return coordinatorRecord{}, err
	}
	newPrevious := registry.PreviousProfile
	if newActive != registry.ActiveProfile {
		newPrevious = registry.ActiveProfile
	}
	record := coordinatorRecord{
		SchemaVersion: coordinatorSchema,
		Operation:     operation, Phase: "prepared",
		OldActive: registry.ActiveProfile, OldPrevious: registry.PreviousProfile,
		NewActive: newActive, NewPrevious: newPrevious, BackupID: backupID,
	}
	if err := writeCoordinator(a.coordinatorPath(), record); err != nil {
		return coordinatorRecord{}, err
	}
	return record, nil
}

func (a *App) beginCoordinatorWithTarget(operation, newActive, backupID string, createdTarget bool) (coordinatorRecord, error) {
	record, err := a.beginCoordinator(operation, newActive, backupID)
	if err != nil {
		return coordinatorRecord{}, err
	}
	record.CreatedTarget = createdTarget
	if err := writeCoordinator(a.coordinatorPath(), record); err != nil {
		return coordinatorRecord{}, err
	}
	return record, nil
}

func (a *App) markCoordinatorLive(record coordinatorRecord) error {
	record.Phase = "live-applied"
	return writeCoordinator(a.coordinatorPath(), record)
}

func (a *App) finishCoordinator() error {
	path := a.coordinatorPath()
	if err := zcode.ValidateSensitivePath(path, true); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("unsafe coordinator journal")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func (a *App) recoverCoordinator() error {
	// Recovery is a write. Do not replay any journal while either the desktop
	// app/CLI or ZCode's own state lock may still own the shared files.
	pending := false
	for _, path := range []string{a.coordinatorPath(), a.Engine.JournalPath(), filepath.Join(a.Config.DataDir, "profile.journal")} {
		if _, statErr := os.Lstat(path); statErr == nil {
			pending = true
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
	}
	if pending {
		if err := a.checkSharedStateLock(); err != nil {
			return err
		}
		running, err := a.running()
		if err != nil {
			return fmt.Errorf("detect ZCode owner for recovery: %w", err)
		}
		if len(running) != 0 {
			return ErrZCodeRunning
		}
	}
	if err := a.Engine.Recover(); err != nil {
		return err
	}
	record, present, err := readCoordinator(a.coordinatorPath())
	if err != nil || !present {
		return err
	}
	if record.Operation == "login" {
		// Login journals begin as rollback-only while the OAuth flow is in
		// progress.  Once the profile and registry are committed the target
		// state marker is written; a crash while removing the journal can then
		// safely finish the successful login instead of deleting it.
		if record.TargetStateRecorded && a.loginCommitMatches(record) {
			return a.finishCoordinator()
		}
		return a.rollbackCoordinator(record)
	}
	completeNew := false
	if record.TargetStateRecorded {
		completeNew = a.targetStateMatches(record)
	} else if record.Operation == "logout" {
		live, credentialsPresent, readErr := a.readLiveOptional()
		completeNew = readErr == nil && !credentialsPresent && !live.TelemetryPresent
	} else if record.NewActive != "" {
		target, loadErr := a.Store.Load(record.NewActive)
		if loadErr == nil {
			live, livePresent, readErr := a.readLiveOptional()
			if readErr == nil && livePresent {
				identity, identityErr := a.Adapter.Identity(live.Credentials)
				authenticated, authErr := a.Adapter.Authenticated(live.Credentials)
				completeNew = identityErr == nil && authErr == nil && authenticated && identity.Provider == target.Metadata.Provider && identity.AccountID == target.Metadata.AccountID && live.TelemetryPresent == target.Bundle.TelemetryPresent && bytes.Equal(live.Credentials, target.Bundle.Credentials) && bytes.Equal(live.Telemetry, target.Bundle.Telemetry)
			}
		}
	}
	if completeNew {
		if err := a.Store.SetActivePair(record.NewActive, record.NewPrevious); err != nil {
			return err
		}
		return a.finishCoordinator()
	}
	return a.rollbackCoordinator(record)
}

func (a *App) loginCommitMatches(record coordinatorRecord) bool {
	if record.NewActive == "" || !a.targetStateMatches(record) {
		return false
	}
	if _, err := a.Store.Load(record.NewActive); err != nil {
		return false
	}
	registry, err := a.Store.Registry()
	return err == nil && registry.ActiveProfile == record.NewActive && registry.PreviousProfile == record.NewPrevious
}

// targetStateMatches verifies a coordinator's exact desired state without
// decrypting or writing any credential bytes to diagnostics.  Hashes are
// sufficient because the transaction engine already authenticates the live
// documents structurally before they reach this layer.
func (a *App) targetStateMatches(record coordinatorRecord) bool {
	live, present, err := a.readLiveOptional()
	if err != nil {
		return false
	}
	credentialsPresent := present && live.Credentials != nil
	if credentialsPresent != record.TargetCredentialsPresent || live.TelemetryPresent != record.TargetTelemetryPresent {
		return false
	}
	if credentialsPresent && checksumBytes(live.Credentials) != record.TargetCredentialsSHA {
		return false
	}
	if record.TargetTelemetryPresent && checksumBytes(live.Telemetry) != record.TargetTelemetrySHA {
		return false
	}
	return true
}

func (a *App) rollbackCoordinator(record coordinatorRecord) error {
	if record.BackupID == "" {
		return fmt.Errorf("coordinator journal has no rollback backup")
	}
	if err := a.checkSharedStateLock(); err != nil {
		return fmt.Errorf("verify shared state is free for recovery: %w", err)
	}
	stoppedAny := false
	if running, err := a.running(); err != nil {
		return err
	} else if len(running) != 0 {
		var stopErr error
		stoppedAny, stopErr = a.stopAll(context.Background())
		if stopErr != nil {
			return fmt.Errorf("stop ZCode for recovery: %w", stopErr)
		}
	}
	if err := a.requireStopped(); err != nil {
		return fmt.Errorf("verify shared state owner stopped for recovery: %w", err)
	}
	bundle, _, _, err := a.restoreBackupID(record.BackupID)
	if err != nil {
		return fmt.Errorf("recover coordinator backup: %w", err)
	}
	if err := a.Engine.Apply(bundle); err != nil {
		return fmt.Errorf("restore coordinator live state: %w", err)
	}
	if err := a.Store.SetActivePair(record.OldActive, record.OldPrevious); err != nil {
		return err
	}
	if record.CreatedTarget && record.NewActive != "" {
		if _, err := a.Store.Load(record.NewActive); err == nil {
			if err := a.Store.Remove(record.NewActive); err != nil {
				return fmt.Errorf("remove incomplete login profile: %w", err)
			}
		} else if !errors.Is(err, profile.ErrNotFound) {
			return err
		}
	}
	if err := a.finishCoordinator(); err != nil {
		return err
	}
	if stoppedAny {
		if err := a.startZCode(); err != nil {
			return fmt.Errorf("restart ZCode after recovery: %w", err)
		}
	}
	return nil
}

func (a *App) applyCoordinated(operation, newActive string, bundle model.SessionBundle, backupID string) error {
	// Engine.Apply intentionally does not create a missing ZCode state
	// directory.  Prepare it before journaling so logout/restore/switch from a
	// first-run or telemetry-only state cannot leave a coordinator journal that
	// can never be replayed.
	if err := a.ensureLiveStateDir(); err != nil {
		return err
	}
	record, err := a.beginCoordinator(operation, newActive, backupID)
	if err != nil {
		return err
	}
	setCoordinatorTarget(&record, bundle)
	if err := writeCoordinator(a.coordinatorPath(), record); err != nil {
		return err
	}
	if err := a.Engine.Apply(bundle); err != nil {
		return err
	}
	if err := a.markCoordinatorLive(record); err != nil {
		return err
	}
	if err := a.Store.SetActivePair(record.NewActive, record.NewPrevious); err != nil {
		return err
	}
	return a.finishCoordinator()
}

func setCoordinatorTarget(record *coordinatorRecord, bundle model.SessionBundle) {
	record.TargetStateRecorded = true
	record.TargetCredentialsPresent = bundle.Credentials != nil
	record.TargetTelemetryPresent = bundle.TelemetryPresent
	record.TargetCredentialsSHA = ""
	record.TargetTelemetrySHA = ""
	if record.TargetCredentialsPresent {
		record.TargetCredentialsSHA = checksumBytes(bundle.Credentials)
	}
	if record.TargetTelemetryPresent {
		record.TargetTelemetrySHA = checksumBytes(bundle.Telemetry)
	}
}

func writeCoordinator(path string, record coordinatorRecord) error {
	if record.SchemaVersion != coordinatorSchema || !validCoordinatorOperation(record.Operation) || (record.Phase != "prepared" && record.Phase != "live-applied") {
		return fmt.Errorf("invalid coordinator journal")
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := zcode.ValidateSensitivePath(path, true); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".coordinator-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := hardenCoordinatorFile(temporaryPath); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("unsafe coordinator journal")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := replaceCoordinatorFile(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func readCoordinator(path string) (coordinatorRecord, bool, error) {
	if err := zcode.ValidateSensitivePath(path, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return coordinatorRecord{}, false, nil
		}
		return coordinatorRecord{}, false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return coordinatorRecord{}, false, nil
	}
	if err != nil {
		return coordinatorRecord{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return coordinatorRecord{}, false, fmt.Errorf("unsafe coordinator journal")
	}
	if !commandPathSecure(path, info) {
		return coordinatorRecord{}, false, fmt.Errorf("unsafe coordinator journal permissions")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return coordinatorRecord{}, false, err
	}
	var record coordinatorRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return coordinatorRecord{}, false, fmt.Errorf("invalid coordinator journal")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return coordinatorRecord{}, false, fmt.Errorf("invalid coordinator journal")
	}
	if record.SchemaVersion != coordinatorSchema || !validCoordinatorOperation(record.Operation) || (record.Phase != "prepared" && record.Phase != "live-applied") {
		return coordinatorRecord{}, false, fmt.Errorf("invalid coordinator journal")
	}
	return record, true, nil
}

func validCoordinatorOperation(operation string) bool {
	switch operation {
	case "switch", "logout", "restore", "login":
		return true
	default:
		return false
	}
}

func checksumBytes(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func syncDirectory(path string) error {
	return syncDirectoryPlatform(path)
}
