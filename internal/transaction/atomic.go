package transaction

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Stage identifies a durable boundary at which a caller may inject a failure
// in tests or diagnostics.  Hooks are invoked after the named event has
// completed, except for the Before* stages.
type Stage string

const (
	StageBeforeJournalWrite      Stage = "before-journal-write"
	StageAfterJournalChmod       Stage = "after-journal-chmod"
	StageAfterJournalSync        Stage = "after-journal-sync"
	StageBeforeJournalRename     Stage = "before-journal-rename"
	StageAfterJournalRename      Stage = "after-journal-rename"
	StageAfterJournalDir         Stage = "after-journal-parent-sync"
	StageBeforeCredentials       Stage = "before-credentials"
	StageAfterCredentialsChmod   Stage = "after-credentials-chmod"
	StageAfterCredentialsTemp    Stage = "after-credentials-temp-sync"
	StageBeforeCredentialsRename Stage = "before-credentials-rename"
	StageAfterCredentials        Stage = "after-credentials-rename"
	StageAfterCredentialsRemove  Stage = "after-credentials-remove"
	StageAfterCredentialsDir     Stage = "after-credentials-parent-sync"
	StageBeforeTelemetry         Stage = "before-telemetry"
	StageAfterTelemetryChmod     Stage = "after-telemetry-chmod"
	StageAfterTelemetryTemp      Stage = "after-telemetry-temp-sync"
	StageBeforeTelemetryRename   Stage = "before-telemetry-rename"
	StageAfterTelemetry          Stage = "after-telemetry-rename"
	StageAfterTelemetryRemove    Stage = "after-telemetry-remove"
	StageAfterTelemetryDir       Stage = "after-telemetry-parent-sync"
	StageBeforeCommitJournal     Stage = "before-commit-journal"
	StageAfterCommitJournal      Stage = "after-commit-journal"
	StageBeforeJournalRemove     Stage = "before-journal-remove"
	StageAfterJournalRemove      Stage = "after-journal-remove"
	StageBeforeRollback          Stage = "before-rollback"
	StageAfterRollback           Stage = "after-rollback"
	StageBeforeBackupWrite       Stage = "before-backup-write"
	StageAfterBackupChmod        Stage = "after-backup-chmod"
	StageAfterBackupWrite        Stage = "after-backup-write"
	StageBeforeBackupRename      Stage = "before-backup-rename"
	StageAfterBackupRename       Stage = "after-backup-rename"
	StageAfterBackupDir          Stage = "after-backup-parent-sync"
	StageBeforeBackupRotate      Stage = "before-backup-rotate"
	StageAfterBackupRotate       Stage = "after-backup-rotate"
)

// FailureInjector is called at durable transaction boundaries.  Returning a
// non-nil error aborts the operation.  Production callers should leave it nil;
// it exists so tests can exercise every crash/failure edge deterministically.
type FailureInjector func(Stage, string) error

func invoke(injector FailureInjector, stage Stage, path string) error {
	if injector == nil {
		return nil
	}
	if err := injector(stage, path); err != nil {
		return fmt.Errorf("injected failure at %s (%s): %w", stage, path, err)
	}
	return nil
}

var tempCounter uint64

func randomSuffix() string {
	var random [8]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err == nil {
		return hex.EncodeToString(random[:])
	}
	// Failure of the system CSPRNG should not make a temp name predictable
	// across concurrent calls.  The counter is only a collision-avoidance
	// fallback; credentials never depend on its secrecy.
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), atomic.AddUint64(&tempCounter, 1))
}

func atomicWrite(path string, payload []byte, mode os.FileMode, injector FailureInjector, stagePrefix string) error {
	path, err := absolutePath(path)
	if err != nil {
		return err
	}
	if _, err := validateTarget(path); err != nil {
		return err
	}
	if mode.Perm() == 0 {
		mode = 0o600
	}
	mode = mode.Perm()
	if err := validateRequestedMode(mode); err != nil {
		return fmt.Errorf("refusing %v for %q", err, path)
	}
	parent := filepath.Dir(path)
	temp := filepath.Join(parent, fmt.Sprintf(".%s.tmp-%d-%s", filepath.Base(path), os.Getpid(), randomSuffix()))

	if err := invoke(injector, stageFor(stagePrefix, "before-write"), path); err != nil {
		return err
	}
	file, err := createAtomicTemp(temp)
	if err != nil {
		return fmt.Errorf("create atomic temp %q: %w", temp, err)
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(temp)
		}
	}()

	if err := writeAll(file, payload); err != nil {
		_ = file.Close()
		return fmt.Errorf("write atomic temp %q: %w", temp, err)
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return fmt.Errorf("chmod atomic temp %q: %w", temp, err)
	}
	if err := invoke(injector, stageFor(stagePrefix, "after-chmod"), path); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync atomic temp %q: %w", temp, err)
	}
	if err := invoke(injector, stageFor(stagePrefix, "after-temp-sync"), path); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close atomic temp %q: %w", temp, err)
	}
	if err := hardenAtomicFile(temp); err != nil {
		return fmt.Errorf("secure atomic temp ACL %q: %w", temp, err)
	}

	// Recheck immediately before rename.  Rename replaces a symlink rather than
	// following it, but rejecting a newly introduced symlink makes the security
	// contract explicit and catches accidental path substitution.
	if _, err := validateTarget(path); err != nil {
		return err
	}
	if err := invoke(injector, stageFor(stagePrefix, "before-rename"), path); err != nil {
		return err
	}
	if err := replaceAtomic(temp, path); err != nil {
		return fmt.Errorf("rename atomic temp %q to %q: %w", temp, path, err)
	}
	removeTemp = false
	if err := invoke(injector, stageFor(stagePrefix, "after-rename"), path); err != nil {
		return err
	}
	if err := syncParent(parent); err != nil {
		return fmt.Errorf("sync parent %q after rename: %w", parent, err)
	}
	if err := invoke(injector, stageFor(stagePrefix, "after-parent-sync"), path); err != nil {
		return err
	}
	return nil
}

func stageFor(prefix, suffix string) Stage {
	if prefix == "journal" {
		switch suffix {
		case "before-write":
			return StageBeforeJournalWrite
		case "after-chmod":
			return StageAfterJournalChmod
		case "after-temp-sync":
			return StageAfterJournalSync
		case "before-rename":
			return StageBeforeJournalRename
		case "after-rename":
			return StageAfterJournalRename
		case "after-parent-sync":
			return StageAfterJournalDir
		}
	}
	if prefix == "backup" {
		switch suffix {
		case "before-write":
			return StageBeforeBackupWrite
		case "after-chmod":
			return StageAfterBackupChmod
		case "after-temp-sync":
			return StageAfterBackupWrite
		case "before-rename":
			return StageBeforeBackupRename
		case "after-rename":
			return StageAfterBackupRename
		case "after-parent-sync":
			return StageAfterBackupDir
		}
	}
	if prefix == "credentials" {
		switch suffix {
		case "before-write":
			return StageBeforeCredentials
		case "after-chmod":
			return StageAfterCredentialsChmod
		case "after-temp-sync":
			return StageAfterCredentialsTemp
		case "before-rename":
			return StageBeforeCredentialsRename
		case "after-rename":
			return StageAfterCredentials
		case "after-remove":
			return StageAfterCredentialsRemove
		case "after-parent-sync":
			return StageAfterCredentialsDir
		}
	}
	if prefix == "telemetry" {
		switch suffix {
		case "before-write":
			return StageBeforeTelemetry
		case "after-chmod":
			return StageAfterTelemetryChmod
		case "after-temp-sync":
			return StageAfterTelemetryTemp
		case "before-rename":
			return StageBeforeTelemetryRename
		case "after-rename":
			return StageAfterTelemetry
		case "after-remove":
			return StageAfterTelemetryRemove
		case "after-parent-sync":
			return StageAfterTelemetryDir
		}
	}
	return Stage(strings.Join([]string{prefix, suffix}, "-"))
}

func writeAll(file *os.File, payload []byte) error {
	for len(payload) > 0 {
		written, err := file.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func syncParent(path string) error {
	path, err := absolutePath(path)
	if err != nil {
		return err
	}
	if err := validateParentDirectory(path); err != nil {
		return err
	}
	return syncParentPlatform(path)
}

func secureRemove(path string, injector FailureInjector, stage Stage) error {
	path, err := absolutePath(path)
	if err != nil {
		return err
	}
	info, err := validateTarget(path)
	if err != nil {
		return err
	}
	if info == nil {
		return nil
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove %q: %w", path, err)
	}
	if err := syncParent(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync parent %q after remove: %w", filepath.Dir(path), err)
	}
	return invoke(injector, stage, path)
}

func readSensitive(path string) (fileState, error) {
	info, err := validateTarget(path)
	if err != nil {
		return fileState{}, err
	}
	if info == nil {
		return fileState{}, nil
	}
	payload, err := readSensitivePlatform(path)
	if err != nil {
		return fileState{}, fmt.Errorf("read %q: %w", path, err)
	}
	return fileState{Present: true, Mode: info.Mode().Perm(), Payload: payload}, nil
}

type fileState struct {
	Present bool
	Mode    os.FileMode
	Payload []byte
}

func restoreSensitive(path string, state fileState, injector FailureInjector, prefix string) error {
	if state.Present {
		return atomicWrite(path, state.Payload, state.Mode, injector, prefix)
	}
	return secureRemove(path, injector, Stage(strings.Join([]string{prefix, "after-remove"}, "-")))
}
