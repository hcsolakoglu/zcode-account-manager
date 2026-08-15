package transaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hcsolakoglu/zcode-auth/internal/model"
)

func sealForTest(payload []byte) ([]byte, error) {
	sealed := make([]byte, len(payload))
	for i, value := range payload {
		sealed[i] = value ^ 0xa5
	}
	return sealed, nil
}

func openForTest(payload []byte) ([]byte, error) { return sealForTest(payload) }

func testEngine(t *testing.T, injector FailureInjector) (*Engine, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	credentials := filepath.Join(dir, "credentials.json")
	telemetry := filepath.Join(dir, "telemetry-state.json")
	journal := filepath.Join(dir, "transaction.journal")
	lock := filepath.Join(dir, "auth.lock")
	if err := os.WriteFile(credentials, []byte("old-credentials"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(telemetry, []byte("old-telemetry"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(StatePaths{Credentials: credentials, Telemetry: telemetry}, TransactionOptions{
		JournalPath:     journal,
		LockPath:        lock,
		Seal:            sealForTest,
		Open:            openForTest,
		FailureInjector: injector,
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine, credentials, telemetry, journal
}

func TestApplyReplacesBundleAndRemovesAbsentTelemetry(t *testing.T) {
	engine, credentials, telemetry, journal := testEngine(t, nil)
	if err := engine.Apply(model.SessionBundle{Credentials: []byte("new-credentials")}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-credentials" {
		t.Fatalf("credentials = %q", got)
	}
	if _, err := os.Stat(telemetry); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("telemetry should be absent, stat error = %v", err)
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal should be removed after commit, stat error = %v", err)
	}
	for _, path := range []string{credentials, telemetry} {
		if info, err := os.Lstat(path); err == nil && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %04o", path, info.Mode().Perm())
		}
	}
}

func TestApplyUsesTelemetryPresenceBit(t *testing.T) {
	engine, _, telemetry, _ := testEngine(t, nil)
	if err := engine.Apply(model.SessionBundle{
		Credentials:      []byte("new"),
		Telemetry:        []byte("present-but-empty-test"),
		TelemetryPresent: true,
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(telemetry); err != nil || string(got) != "present-but-empty-test" {
		t.Fatalf("present telemetry = %q, err = %v", got, err)
	}
	if err := engine.Apply(model.SessionBundle{Credentials: []byte("newer"), Telemetry: []byte("stale"), TelemetryPresent: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(telemetry); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("telemetry should be removed when presence bit is false, err = %v", err)
	}
}

func TestApplyRequiresProtectedJournalBeforeChangingLiveState(t *testing.T) {
	dir := t.TempDir()
	credentials := filepath.Join(dir, "credentials.json")
	telemetry := filepath.Join(dir, "telemetry-state.json")
	if err := os.WriteFile(credentials, []byte("old-c"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(telemetry, []byte("old-t"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(StatePaths{Credentials: credentials, Telemetry: telemetry}, TransactionOptions{JournalPath: filepath.Join(dir, "journal")})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Apply(model.SessionBundle{Credentials: []byte("new")}); !errors.Is(err, ErrJournalProtectionRequired) {
		t.Fatalf("error = %v, want ErrJournalProtectionRequired", err)
	}
	if got, _ := os.ReadFile(credentials); string(got) != "old-c" {
		t.Fatalf("credentials changed without protected journal: %q", got)
	}
	if got, _ := os.ReadFile(telemetry); string(got) != "old-t" {
		t.Fatalf("telemetry changed without protected journal: %q", got)
	}
}

func TestFailureInjectionRollsBackAtEveryPreCommitBoundary(t *testing.T) {
	stages := []Stage{
		StageBeforeJournalWrite,
		StageAfterJournalChmod,
		StageAfterJournalSync,
		StageBeforeJournalRename,
		StageAfterJournalRename,
		StageAfterJournalDir,
		StageBeforeCredentials,
		StageAfterCredentialsChmod,
		StageAfterCredentialsTemp,
		StageBeforeCredentialsRename,
		StageAfterCredentials,
		StageAfterCredentialsDir,
		StageBeforeTelemetry,
		StageAfterTelemetryChmod,
		StageAfterTelemetryTemp,
		StageBeforeTelemetryRename,
		StageAfterTelemetry,
		StageAfterTelemetryDir,
		StageBeforeCommitJournal,
	}
	for _, wantStage := range stages {
		wantStage := wantStage
		t.Run(string(wantStage), func(t *testing.T) {
			var once sync.Once
			injector := func(stage Stage, _ string) error {
				if stage != wantStage {
					return nil
				}
				var injected bool
				once.Do(func() { injected = true })
				if injected {
					return errors.New("test failure")
				}
				return nil
			}
			engine, credentials, telemetry, journal := testEngine(t, injector)
			err := engine.Apply(model.SessionBundle{Credentials: []byte("new-c"), Telemetry: []byte("new-t"), TelemetryPresent: true})
			if err == nil {
				t.Fatal("Apply unexpectedly succeeded")
			}
			if got, readErr := os.ReadFile(credentials); readErr != nil || string(got) != "old-credentials" {
				t.Fatalf("credentials = %q, read error = %v", got, readErr)
			}
			if got, readErr := os.ReadFile(telemetry); readErr != nil || string(got) != "old-telemetry" {
				t.Fatalf("telemetry = %q, read error = %v", got, readErr)
			}
			if _, statErr := os.Stat(journal); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("journal = %v, want removed after rollback", statErr)
			}
		})
	}
}

func TestJournalIsEncryptedAndRecoverable(t *testing.T) {
	engine, credentials, telemetry, journal := testEngine(t, nil)
	oldCredentials, err := readSensitive(credentials)
	if err != nil {
		t.Fatal(err)
	}
	oldTelemetry, err := readSensitive(telemetry)
	if err != nil {
		t.Fatal(err)
	}
	record, err := engine.newJournal(oldCredentials, oldTelemetry)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.writeJournal(record, false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("old-credentials")) || bytes.Contains(raw, []byte("old-telemetry")) {
		t.Fatalf("journal contains plaintext payload: %q", raw)
	}
	if err := os.WriteFile(credentials, []byte("partial-new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.Recover(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(credentials); string(got) != "old-credentials" {
		t.Fatalf("recovered credentials = %q", got)
	}
	if got, _ := os.ReadFile(telemetry); string(got) != "old-telemetry" {
		t.Fatalf("recovered telemetry = %q", got)
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal remains after recovery: %v", err)
	}
}

func TestCommittedJournalRecoveryKeepsNewState(t *testing.T) {
	engine, credentials, telemetry, journal := testEngine(t, nil)
	oldCredentials, _ := readSensitive(credentials)
	oldTelemetry, _ := readSensitive(telemetry)
	record, err := engine.newJournal(oldCredentials, oldTelemetry)
	if err != nil {
		t.Fatal(err)
	}
	record.Phase = journalPhaseCommitted
	if err := engine.writeJournal(record, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentials, []byte("new-c"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(telemetry); err != nil {
		t.Fatal(err)
	}
	if err := engine.Recover(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(credentials); string(got) != "new-c" {
		t.Fatalf("committed credentials rolled back: %q", got)
	}
	if _, err := os.Stat(telemetry); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed telemetry should remain absent: %v", err)
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed journal remains: %v", err)
	}
}

func TestLockPermissionsAndSymlinkRejection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.lock")
	lock, err := AcquireExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %04o", info.Mode().Perm())
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.lock")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireExclusive(link); err == nil {
		t.Fatal("symlink lock unexpectedly accepted")
	}
}

func TestExclusiveLockSerializesConcurrentCallers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.lock")
	first, err := AcquireExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	acquired := make(chan *Lock, 1)
	errorsCh := make(chan error, 1)
	go func() {
		close(started)
		lock, err := AcquireExclusive(path)
		if err != nil {
			errorsCh <- err
			return
		}
		acquired <- lock
	}()
	<-started
	select {
	case lock := <-acquired:
		_ = lock.Close()
		t.Fatal("second exclusive lock bypassed first")
	case err := <-errorsCh:
		t.Fatal(err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case lock := <-acquired:
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
	case err := <-errorsCh:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("second exclusive lock did not proceed after release")
	}
}

func TestStateSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	credentials := filepath.Join(dir, "credentials.json")
	telemetry := filepath.Join(dir, "telemetry-state.json")
	target := filepath.Join(dir, "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, credentials); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(telemetry, []byte("telemetry"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(StatePaths{Credentials: credentials, Telemetry: telemetry}, TransactionOptions{Seal: sealForTest, Open: openForTest})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Apply(model.SessionBundle{Credentials: []byte("new")}); err == nil {
		t.Fatal("symlink state unexpectedly accepted")
	}
	if got, _ := os.ReadFile(target); string(got) != "outside" {
		t.Fatalf("symlink target changed: %q", got)
	}
}

func TestBackupRotationKeepsManualBackupsAndValidatesChecksums(t *testing.T) {
	dir := t.TempDir()
	store, err := NewBackupStore(filepath.Join(dir, "backups"), BackupStoreOptions{AutomaticLimit: 2})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 3; i++ {
		id := "auto-" + string(rune('a'+i))
		if _, err := store.CreateAutomatic(model.BackupMetadata{ID: id, CreatedAt: base.Add(time.Duration(i) * time.Minute)}, EncryptedSessionBundle{
			Credentials:        []byte{byte(i + 1), 0x7f},
			Telemetry:          []byte{byte(i + 4)},
			CredentialsPresent: true,
			TelemetryPresent:   true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	manual, err := store.CreateManual(model.BackupMetadata{ID: "manual-a", CreatedAt: base.Add(10 * time.Minute)}, EncryptedSessionBundle{Credentials: []byte{0x11}, CredentialsPresent: true})
	if err != nil {
		t.Fatal(err)
	}
	if manual.Kind != Manual {
		t.Fatalf("manual kind = %q", manual.Kind)
	}
	list, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	automaticCount := 0
	manualCount := 0
	for _, backup := range list {
		switch backup.Kind {
		case Automatic:
			automaticCount++
		case Manual:
			manualCount++
		}
		raw, readErr := os.ReadFile(backup.Path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Contains(raw, []byte("old-credentials")) || bytes.Contains(raw, []byte("refresh-token")) {
			t.Fatalf("backup contains plaintext token: %q", raw)
		}
	}
	if automaticCount != 2 || manualCount != 1 {
		t.Fatalf("backup counts automatic=%d manual=%d, list=%+v", automaticCount, manualCount, list)
	}
	if _, err := store.Restore("auto-a"); err == nil {
		t.Fatal("rotated automatic backup unexpectedly restorable")
	}
	restored, err := store.Restore("auto-c")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Payload.Credentials, []byte{3, 0x7f}) {
		t.Fatalf("restored encrypted credentials = %v", restored.Payload.Credentials)
	}
	if _, err := store.Restore("manual-a"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(restored.Path)
	if err != nil {
		t.Fatal(err)
	}
	var record backupRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	record.Payload.Credentials[0] ^= 0xff
	corrupt, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restored.Path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Restore("auto-c"); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corrupt restore error = %v", err)
	}
}
