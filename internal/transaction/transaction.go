package transaction

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hcsolakoglu/zcode-auth/internal/model"
)

const journalSchemaVersion = 1

var (
	// ErrJournalProtectionRequired means a transaction would have to persist
	// existing credentials in its crash-recovery journal, but no caller-owned
	// encryption/sealing function was supplied.
	ErrJournalProtectionRequired = errors.New("transaction journal requires a payload sealer")
	// ErrInvalidJournal is returned when a journal is malformed, points at a
	// different state path, or fails payload/checksum validation.
	ErrInvalidJournal = errors.New("invalid transaction journal")
)

// PayloadSealer and PayloadOpener are supplied by the profile/crypto layer.
// The transaction package deliberately does not persist plaintext credential
// snapshots.  Seal must return an authenticated encrypted representation;
// Open must reverse it and authenticate it.
type PayloadSealer func([]byte) ([]byte, error)
type PayloadOpener func([]byte) ([]byte, error)

// StatePaths identifies the two live documents that form one indivisible
// session.  Credentials and Telemetry are the preferred fields.  The Path
// spellings are accepted as aliases for callers that use path-oriented names.
type StatePaths struct {
	Credentials string
	Telemetry   string

	CredentialsPath string
	TelemetryPath   string
}

func (p StatePaths) normalized() (StatePaths, error) {
	credentials := p.Credentials
	if credentials == "" {
		credentials = p.CredentialsPath
	}
	telemetry := p.Telemetry
	if telemetry == "" {
		telemetry = p.TelemetryPath
	}
	if credentials == "" || telemetry == "" {
		return StatePaths{}, errors.New("both credentials and telemetry paths are required")
	}
	credentials, err := absolutePath(credentials)
	if err != nil {
		return StatePaths{}, fmt.Errorf("credentials path: %w", err)
	}
	telemetry, err = absolutePath(telemetry)
	if err != nil {
		return StatePaths{}, fmt.Errorf("telemetry path: %w", err)
	}
	if credentials == telemetry {
		return StatePaths{}, errors.New("credentials and telemetry paths must differ")
	}
	return StatePaths{Credentials: credentials, Telemetry: telemetry}, nil
}

// TransactionOptions configures an Engine.
type TransactionOptions struct {
	// JournalPath is the recoverable on-disk journal.  If empty, a private
	// journal beside the credentials document is used.
	JournalPath string
	// LockPath is the shared auth lock.  If empty, the caller is expected to
	// hold a lock itself.  Supplying it makes Apply and Recover self-locking.
	LockPath string

	Seal PayloadSealer
	Open PayloadOpener

	// Encrypt and Decrypt are aliases retained for callers that use crypto
	// terminology.  Seal/Open take precedence when both are provided.
	Encrypt PayloadSealer
	Decrypt PayloadOpener

	FailureInjector FailureInjector
}

// Engine atomically rotates a SessionBundle across credentials.json and
// telemetry-state.json.  A filesystem rename is atomic per document; the
// durable journal makes the pair recoverable as one old-or-new state after a
// crash or partial failure.
type Engine struct {
	paths    StatePaths
	journal  string
	lockPath string
	seal     PayloadSealer
	open     PayloadOpener
	injector FailureInjector
}

// NewEngine validates state paths and returns a transaction engine.  No live
// state is read or modified until Apply or Recover is called.
func NewEngine(paths StatePaths, options TransactionOptions) (*Engine, error) {
	normalized, err := paths.normalized()
	if err != nil {
		return nil, err
	}
	journal := options.JournalPath
	if journal == "" {
		journal = filepath.Join(filepath.Dir(normalized.Credentials), ".zcode-auth.transaction.json")
	}
	journal, err = absolutePath(journal)
	if err != nil {
		return nil, fmt.Errorf("journal path: %w", err)
	}
	if journal == normalized.Credentials || journal == normalized.Telemetry {
		return nil, errors.New("journal path must differ from state paths")
	}
	lockPath := options.LockPath
	if lockPath != "" {
		lockPath, err = absolutePath(lockPath)
		if err != nil {
			return nil, fmt.Errorf("lock path: %w", err)
		}
	}
	seal := options.Seal
	if seal == nil {
		seal = options.Encrypt
	}
	open := options.Open
	if open == nil {
		open = options.Decrypt
	}
	return &Engine{
		paths:    normalized,
		journal:  journal,
		lockPath: lockPath,
		seal:     seal,
		open:     open,
		injector: options.FailureInjector,
	}, nil
}

// Paths returns the normalized live state paths.
func (e *Engine) Paths() StatePaths { return e.paths }

// JournalPath returns the path used for crash recovery.
func (e *Engine) JournalPath() string { return e.journal }

// Apply replaces both live documents with bundle.  A nil Credentials slice
// removes credentials.json.  TelemetryPresent is authoritative: false removes
// telemetry-state.json even if Telemetry contains stale bytes, while true
// creates the file (including for a non-nil empty slice).
func (e *Engine) Apply(bundle model.SessionBundle) error {
	if e == nil {
		return errors.New("nil transaction engine")
	}
	unlock, err := e.acquire(Exclusive)
	if err != nil {
		return err
	}
	if unlock != nil {
		defer func() { _ = unlock.Close() }()
	}
	if err := e.recoverLocked(); err != nil {
		return fmt.Errorf("recover pending transaction: %w", err)
	}
	return e.applyLocked(bundle)
}

// ReplaceBundle is an explicit alias for Apply.
func (e *Engine) ReplaceBundle(bundle model.SessionBundle) error { return e.Apply(bundle) }

// Recover rolls back an incomplete journal, or removes a committed journal.
// It is safe to call at startup and before every new Apply.
func (e *Engine) Recover() error {
	if e == nil {
		return errors.New("nil transaction engine")
	}
	unlock, err := e.acquire(Exclusive)
	if err != nil {
		return err
	}
	if unlock != nil {
		defer func() { _ = unlock.Close() }()
	}
	return e.recoverLocked()
}

func (e *Engine) acquire(mode LockMode) (*Lock, error) {
	if e.lockPath == "" {
		return nil, nil
	}
	lock, err := Acquire(e.lockPath, mode)
	if err != nil {
		return nil, fmt.Errorf("acquire transaction lock: %w", err)
	}
	return lock, nil
}

func (e *Engine) applyLocked(bundle model.SessionBundle) error {
	oldCredentials, err := readSensitive(e.paths.Credentials)
	if err != nil {
		return fmt.Errorf("capture credentials: %w", err)
	}
	oldTelemetry, err := readSensitive(e.paths.Telemetry)
	if err != nil {
		return fmt.Errorf("capture telemetry: %w", err)
	}
	record, err := e.newJournal(oldCredentials, oldTelemetry)
	if err != nil {
		return err
	}
	if err := e.writeJournal(record, false); err != nil {
		// A failure after rename can leave a complete prepared journal even
		// though Apply has not reached its first state-file write.  Reuse the
		// normal recovery path so no durable journal or partial operation is
		// abandoned on this early edge.
		if recoverErr := e.recoverLocked(); recoverErr != nil {
			return errors.Join(fmt.Errorf("prepare transaction journal: %w", err), fmt.Errorf("recover failed journal: %w", recoverErr))
		}
		return fmt.Errorf("prepare transaction journal: %w", err)
	}

	fail := func(cause error) error {
		rollbackErr := e.rollback(record)
		if rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("rollback failed; journal retained for recovery: %w", rollbackErr))
		}
		if removeErr := e.removeJournal(); removeErr != nil {
			return errors.Join(cause, fmt.Errorf("remove rollback journal: %w", removeErr))
		}
		return cause
	}

	if err := e.writeDesired(e.paths.Credentials, bundle.Credentials != nil, bundle.Credentials, "credentials"); err != nil {
		return fail(fmt.Errorf("replace credentials: %w", err))
	}
	record.Phase = journalPhaseCredentials
	if err := e.writeJournal(record, false); err != nil {
		return fail(fmt.Errorf("commit credentials phase: %w", err))
	}

	if err := e.writeDesired(e.paths.Telemetry, bundle.TelemetryPresent, bundle.Telemetry, "telemetry"); err != nil {
		return fail(fmt.Errorf("replace telemetry: %w", err))
	}
	record.Phase = journalPhaseTelemetry
	if err := e.writeJournal(record, false); err != nil {
		return fail(fmt.Errorf("commit telemetry phase: %w", err))
	}

	record.Phase = journalPhaseCommitted
	if err := e.writeJournal(record, true); err != nil {
		return fail(fmt.Errorf("commit transaction journal: %w", err))
	}
	if err := invoke(e.injector, StageAfterCommitJournal, e.journal); err != nil {
		// Both live files are already the new, durable state.  Retaining a
		// committed journal is safe; Recover will remove it without rolling
		// back a successful transaction.
		return fmt.Errorf("transaction committed but post-commit hook failed: %w", err)
	}
	if err := e.removeJournal(); err != nil {
		// The committed marker is intentionally left in place.  This is a
		// successful new state and remains recoverable, rather than risking a
		// destructive rollback after the commit point.
		return fmt.Errorf("transaction committed but journal cleanup failed: %w", err)
	}
	return nil
}

func (e *Engine) writeDesired(path string, present bool, payload []byte, prefix string) error {
	if present {
		return atomicWrite(path, payload, 0o600, e.injector, prefix)
	}
	if err := invoke(e.injector, stageFor(prefix, "before-write"), path); err != nil {
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
	if err := invoke(e.injector, stageFor(prefix, "after-remove"), path); err != nil {
		return err
	}
	if err := syncParent(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync parent %q after remove: %w", filepath.Dir(path), err)
	}
	return invoke(e.injector, stageFor(prefix, "after-parent-sync"), path)
}

func (e *Engine) newJournal(credentials, telemetry fileState) (journalRecord, error) {
	credentialsSnapshot, err := e.snapshot(credentials, "credentials")
	if err != nil {
		return journalRecord{}, err
	}
	telemetrySnapshot, err := e.snapshot(telemetry, "telemetry")
	if err != nil {
		return journalRecord{}, err
	}
	return journalRecord{
		SchemaVersion:  journalSchemaVersion,
		ID:             newIdentifier(),
		Phase:          journalPhasePrepared,
		Credentials:    e.paths.Credentials,
		Telemetry:      e.paths.Telemetry,
		CreatedAt:      time.Now().UTC(),
		OldCredentials: credentialsSnapshot,
		OldTelemetry:   telemetrySnapshot,
	}, nil
}

func (e *Engine) snapshot(state fileState, label string) (journalSnapshot, error) {
	snapshot := journalSnapshot{Present: state.Present, Mode: uint32(state.Mode.Perm())}
	if !state.Present {
		return snapshot, nil
	}
	if e.seal == nil {
		return journalSnapshot{}, fmt.Errorf("%w for %s", ErrJournalProtectionRequired, label)
	}
	sealed, err := e.seal(state.Payload)
	if err != nil {
		return journalSnapshot{}, fmt.Errorf("seal old %s payload: %w", label, err)
	}
	if len(state.Payload) > 0 && len(sealed) == 0 {
		return journalSnapshot{}, fmt.Errorf("seal old %s payload: empty result", label)
	}
	if len(state.Payload) > 0 && string(sealed) == string(state.Payload) {
		return journalSnapshot{}, fmt.Errorf("seal old %s payload returned plaintext", label)
	}
	snapshot.Payload = sealed
	snapshot.SHA256 = checksum(state.Payload)
	// Never restore a pre-existing insecure mode.  Live auth files are private
	// by contract; normalization to 0600 avoids reintroducing a leak on rollback.
	if snapshot.Mode&0o077 != 0 {
		snapshot.Mode = 0o600
	}
	if snapshot.Mode == 0 {
		snapshot.Mode = 0o600
	}
	return snapshot, nil
}

func (e *Engine) writeJournal(record journalRecord, committing bool) error {
	if committing {
		if err := invoke(e.injector, StageBeforeCommitJournal, e.journal); err != nil {
			return err
		}
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal journal: %w", err)
	}
	if err := atomicWrite(e.journal, payload, 0o600, e.injector, "journal"); err != nil {
		return err
	}
	return nil
}

func (e *Engine) rollback(record journalRecord) error {
	if err := invoke(e.injector, StageBeforeRollback, e.journal); err != nil {
		return err
	}
	credentials, err := e.restoreSnapshot(record.OldCredentials, "credentials")
	if err != nil {
		return err
	}
	telemetry, err := e.restoreSnapshot(record.OldTelemetry, "telemetry")
	if err != nil {
		return err
	}
	if err := restoreSensitive(e.paths.Credentials, credentials, nil, "credentials"); err != nil {
		return fmt.Errorf("restore credentials: %w", err)
	}
	if err := restoreSensitive(e.paths.Telemetry, telemetry, nil, "telemetry"); err != nil {
		return fmt.Errorf("restore telemetry: %w", err)
	}
	return invoke(e.injector, StageAfterRollback, e.journal)
}

func (e *Engine) restoreSnapshot(snapshot journalSnapshot, label string) (fileState, error) {
	state := fileState{Present: snapshot.Present, Mode: os.FileMode(snapshot.Mode).Perm()}
	if !snapshot.Present {
		return state, nil
	}
	if e.open == nil {
		return fileState{}, fmt.Errorf("%w for %s recovery", ErrJournalProtectionRequired, label)
	}
	payload, err := e.open(snapshot.Payload)
	if err != nil {
		return fileState{}, fmt.Errorf("open journal %s payload: %w", label, err)
	}
	if snapshot.SHA256 == "" || checksum(payload) != snapshot.SHA256 {
		return fileState{}, fmt.Errorf("%w: %s payload checksum mismatch", ErrInvalidJournal, label)
	}
	if state.Mode == 0 || state.Mode&0o077 != 0 {
		state.Mode = 0o600
	}
	state.Payload = payload
	return state, nil
}

func (e *Engine) recoverLocked() error {
	record, present, err := e.readJournal()
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if record.Phase == journalPhaseCommitted {
		return e.removeJournal()
	}
	if err := e.rollback(record); err != nil {
		return fmt.Errorf("recover transaction %s: %w", record.ID, err)
	}
	if err := e.removeJournal(); err != nil {
		return fmt.Errorf("remove recovered journal: %w", err)
	}
	return nil
}

func (e *Engine) readJournal() (journalRecord, bool, error) {
	info, err := validateTarget(e.journal)
	if err != nil {
		return journalRecord{}, false, err
	}
	if info == nil {
		return journalRecord{}, false, nil
	}
	if !privateFilePermissions(e.journal, info) {
		return journalRecord{}, false, fmt.Errorf("%w: journal permissions are %04o", ErrInvalidJournal, info.Mode().Perm())
	}
	payload, err := os.ReadFile(e.journal)
	if err != nil {
		return journalRecord{}, false, fmt.Errorf("read journal: %w", err)
	}
	var record journalRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return journalRecord{}, false, fmt.Errorf("%w: decode journal: %v", ErrInvalidJournal, err)
	}
	if record.SchemaVersion != journalSchemaVersion || record.ID == "" {
		return journalRecord{}, false, fmt.Errorf("%w: unsupported schema or missing id", ErrInvalidJournal)
	}
	if record.CreatedAt.IsZero() {
		return journalRecord{}, false, fmt.Errorf("%w: missing creation time", ErrInvalidJournal)
	}
	switch record.Phase {
	case journalPhasePrepared, journalPhaseCredentials, journalPhaseTelemetry, journalPhaseCommitted:
	default:
		return journalRecord{}, false, fmt.Errorf("%w: unknown phase %q", ErrInvalidJournal, record.Phase)
	}
	if filepath.Clean(record.Credentials) != e.paths.Credentials || filepath.Clean(record.Telemetry) != e.paths.Telemetry {
		return journalRecord{}, false, fmt.Errorf("%w: journal paths do not match engine", ErrInvalidJournal)
	}
	if record.Phase != journalPhaseCommitted {
		if _, err := e.restoreSnapshot(record.OldCredentials, "credentials"); err != nil {
			return journalRecord{}, false, err
		}
		if _, err := e.restoreSnapshot(record.OldTelemetry, "telemetry"); err != nil {
			return journalRecord{}, false, err
		}
	}
	return record, true, nil
}

func (e *Engine) removeJournal() error {
	if err := invoke(e.injector, StageBeforeJournalRemove, e.journal); err != nil {
		return err
	}
	info, err := validateTarget(e.journal)
	if err != nil {
		return err
	}
	if info == nil {
		return nil
	}
	if err := os.Remove(e.journal); err != nil {
		return fmt.Errorf("remove journal: %w", err)
	}
	if err := syncParent(filepath.Dir(e.journal)); err != nil {
		return fmt.Errorf("sync journal directory: %w", err)
	}
	return invoke(e.injector, StageAfterJournalRemove, e.journal)
}

type journalPhase string

const (
	journalPhasePrepared    journalPhase = "prepared"
	journalPhaseCredentials journalPhase = "credentials-committed"
	journalPhaseTelemetry   journalPhase = "telemetry-committed"
	journalPhaseCommitted   journalPhase = "committed"
)

type journalRecord struct {
	SchemaVersion  int             `json:"schema_version"`
	ID             string          `json:"id"`
	Phase          journalPhase    `json:"phase"`
	Credentials    string          `json:"credentials_path"`
	Telemetry      string          `json:"telemetry_path"`
	CreatedAt      time.Time       `json:"created_at"`
	OldCredentials journalSnapshot `json:"old_credentials"`
	OldTelemetry   journalSnapshot `json:"old_telemetry"`
}

type journalSnapshot struct {
	Present bool   `json:"present"`
	Mode    uint32 `json:"mode"`
	Payload []byte `json:"payload,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

func checksum(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func newIdentifier() string {
	return fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), randomSuffix())
}
