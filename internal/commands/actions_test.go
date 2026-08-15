package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hcsolakoglu/zcode-account-manager/internal/config"
	"github.com/hcsolakoglu/zcode-account-manager/internal/model"
	zprocess "github.com/hcsolakoglu/zcode-account-manager/internal/process"
	"github.com/hcsolakoglu/zcode-account-manager/internal/profile"
	"github.com/hcsolakoglu/zcode-account-manager/internal/transaction"
	"github.com/hcsolakoglu/zcode-account-manager/internal/zcode"
)

type commandFixture struct {
	t     *testing.T
	app   *App
	paths zcode.Paths
	state map[int]bool
}

func newCommandFixture(t *testing.T) *commandFixture {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	stateDir := filepath.Join(root, "zcode")
	paths := zcode.PathsForStateDir(stateDir).WithExecutable(filepath.Join(root, "zcode-bin"))
	if err := os.WriteFile(paths.Executable, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	key := []byte("01234567890123456789012345678901")
	store, err := profile.NewStoreWithKey(dataDir, key)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := transaction.NewEngine(transaction.StatePaths{
		Credentials: paths.CredentialsPath,
		Telemetry:   paths.TelemetryPath,
	}, transaction.TransactionOptions{
		JournalPath: filepath.Join(dataDir, "live-state.journal"),
		Seal: func(payload []byte) ([]byte, error) {
			return store.SealPayload("transaction-journal", payload)
		},
		Open: func(payload []byte) ([]byte, error) {
			return store.OpenPayload("transaction-journal", payload)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	backups, err := transaction.NewBackupStore(filepath.Join(dataDir, "backups"), transaction.BackupStoreOptions{AutomaticLimit: 2})
	if err != nil {
		t.Fatal(err)
	}
	adapter := zcode.NewAdapter(paths)
	fixture := &commandFixture{t: t, paths: paths, state: map[int]bool{}}
	app, err := NewWithOptions(Options{
		Config: config.Config{
			DataDir:         dataDir,
			ZCodeStateDir:   stateDir,
			ZCodeExecutable: paths.Executable,
			BackupLimit:     2,
			StopTimeoutSec:  1,
			LoginTimeoutSec: 1,
		},
		Adapter: adapter,
		Store:   store,
		Engine:  engine,
		Backups: backups,
		Out:     new(bytes.Buffer),
		ErrOut:  new(bytes.Buffer),
		Now:     func() time.Time { return time.Unix(1700000000, 0).UTC() },
		Detect: func() ([]zprocess.Info, error) {
			if fixture.state[1] {
				return []zprocess.Info{{PID: 1, Executable: paths.Executable}}, nil
			}
			return nil, nil
		},
		Stop: func(_ context.Context, _ zprocess.Info, _ zprocess.StopOptions) error {
			fixture.state[1] = false
			return nil
		},
		Start: func(_ zprocess.StartOptions) (*os.Process, error) {
			fixture.state[1] = true
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.app = app
	return fixture
}

func commandCredentials(account, token string) []byte {
	return []byte(fmt.Sprintf(`{"provider":"zai","account_id":%q,"access_token":%q,"refresh_token":"refresh-%s","unknown":{"future":true}}`, account, token, account))
}

func TestStopAllPreflightsBundledCLIWithoutStoppingDesktop(t *testing.T) {
	fixture := newCommandFixture(t)
	stopCalls := 0
	fixture.app.Detect = func() ([]zprocess.Info, error) {
		return []zprocess.Info{
			{PID: 10, Product: "desktop"},
			{PID: 11, Product: "cli"},
		}, nil
	}
	fixture.app.Stop = func(context.Context, zprocess.Info, zprocess.StopOptions) error {
		stopCalls++
		return nil
	}
	stopped, err := fixture.app.stopAll(context.Background())
	if !errors.Is(err, ErrSharedStateOwner) || stopped || stopCalls != 0 {
		t.Fatalf("stopAll stopped=%v calls=%d err=%v", stopped, stopCalls, err)
	}
}

func (f *commandFixture) writeLive(credentials []byte, telemetry []byte, present bool) {
	f.t.Helper()
	if err := zcode.WriteState(f.paths, model.SessionBundle{Credentials: credentials, Telemetry: telemetry, TelemetryPresent: present}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *commandFixture) load(alias string) model.SessionBundle {
	f.t.Helper()
	profile, err := f.app.Store.Load(alias)
	if err != nil {
		f.t.Fatal(err)
	}
	return profile.Bundle
}

func TestSwitchSynchronizesRefreshAndRotatesExactTelemetry(t *testing.T) {
	f := newCommandFixture(t)
	credentialA := commandCredentials("account-a", "token-a1")
	credentialB := commandCredentials("account-b", "token-b1")
	telemetryA := []byte(`{"deviceMid":"device-a","future":1}`)

	f.writeLive(credentialA, telemetryA, true)
	if err := f.app.Save("a", false); err != nil {
		t.Fatal(err)
	}
	f.writeLive(credentialB, nil, false)
	if err := f.app.Save("b", false); err != nil {
		t.Fatal(err)
	}

	if err := f.app.Switch(context.Background(), "a", false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(f.paths.TelemetryPath)
	if err != nil || !bytes.Equal(got, telemetryA) {
		t.Fatalf("A telemetry was not restored exactly: %q err=%v", got, err)
	}
	refreshedA := commandCredentials("account-a", "token-a2")
	f.writeLive(refreshedA, []byte(`{"deviceMid":"device-a2"}`), true)
	if err := f.app.Switch(context.Background(), "b", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.paths.TelemetryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("B telemetry should remain absent: %v", err)
	}
	if !bytes.Equal(f.load("a").Credentials, refreshedA) || string(f.load("a").Telemetry) != `{"deviceMid":"device-a2"}` {
		t.Fatal("switch did not synchronize refreshed A bundle")
	}
	if err := f.app.Switch(context.Background(), "-", false); err != nil {
		t.Fatal(err)
	}
	state, err := zcode.ReadState(f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.Credentials, refreshedA) || !bytes.Equal(state.Telemetry, []byte(`{"deviceMid":"device-a2"}`)) || !state.TelemetryPresent {
		t.Fatalf("A -> B -> A state mismatch: %+v", state)
	}
}

func TestSwitchAbortsIfZCodeAppearsImmediatelyBeforeApply(t *testing.T) {
	f := newCommandFixture(t)
	credentialsA := commandCredentials("account-a", "token-a")
	credentialsB := commandCredentials("account-b", "token-b")
	f.writeLive(credentialsA, []byte(`{"deviceMid":"a"}`), true)
	if err := f.app.Save("a", false); err != nil {
		t.Fatal(err)
	}
	f.writeLive(credentialsB, []byte(`{"deviceMid":"b"}`), true)
	if err := f.app.Save("b", false); err != nil {
		t.Fatal(err)
	}
	f.writeLive(credentialsA, []byte(`{"deviceMid":"a"}`), true)
	detections := 0
	f.app.Detect = func() ([]zprocess.Info, error) {
		detections++
		if detections >= 3 {
			return []zprocess.Info{{PID: 99, Executable: f.paths.Executable}}, nil
		}
		return nil, nil
	}
	if err := f.app.Switch(context.Background(), "b", false); !errors.Is(err, ErrZCodeRunning) {
		t.Fatalf("Switch error = %v, want ErrZCodeRunning", err)
	}
	state, err := zcode.ReadState(f.paths)
	if err != nil || !bytes.Equal(state.Credentials, credentialsA) || string(state.Telemetry) != `{"deviceMid":"a"}` {
		t.Fatalf("switch mutated after process race: %+v err=%v", state, err)
	}
}

func TestLoginFailureRollsBackLiveStateRegistryAndTelemetry(t *testing.T) {
	f := newCommandFixture(t)
	oldCredentials := commandCredentials("account-a", "token-a")
	oldTelemetry := []byte(`{"deviceMid":"device-a"}`)
	f.writeLive(oldCredentials, oldTelemetry, true)
	if err := f.app.Save("a", false); err != nil {
		t.Fatal(err)
	}
	f.app.WaitAuth = func(context.Context, zcode.WatchOptions) (model.SessionBundle, error) {
		return model.SessionBundle{}, errors.New("oauth cancelled")
	}
	if err := f.app.Login(context.Background(), "new"); err == nil || !strings.Contains(err.Error(), "oauth cancelled") {
		t.Fatalf("Login error = %v", err)
	}
	state, err := zcode.ReadState(f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.Credentials, oldCredentials) || !bytes.Equal(state.Telemetry, oldTelemetry) {
		t.Fatal("login failure did not restore the old live bundle")
	}
	registry, err := f.app.Store.Registry()
	if err != nil {
		t.Fatal(err)
	}
	if registry.ActiveProfile != "a" || registry.PreviousProfile != "" {
		t.Fatalf("registry after failed login = %+v", registry)
	}
	if _, err := f.app.Store.Load("new"); !errors.Is(err, profile.ErrNotFound) {
		t.Fatalf("failed login profile remains: %v", err)
	}
	if _, _, err := readCoordinator(f.app.coordinatorPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.app.coordinatorPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("coordinator journal remains after rollback: %v", err)
	}
}

func TestLoginSuccessCapturesReturnedBundleAndCleansCoordinator(t *testing.T) {
	f := newCommandFixture(t)
	credentials := commandCredentials("account-new", "token-new")
	telemetry := []byte(`{"deviceMid":"device-new"}`)
	f.app.WaitAuth = func(context.Context, zcode.WatchOptions) (model.SessionBundle, error) {
		f.writeLive(credentials, telemetry, true)
		return model.SessionBundle{Credentials: credentials, Telemetry: telemetry, TelemetryPresent: true}, nil
	}
	if err := f.app.Login(context.Background(), "new"); err != nil {
		t.Fatal(err)
	}
	state, err := zcode.ReadState(f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.Credentials, credentials) || !bytes.Equal(state.Telemetry, telemetry) || !state.TelemetryPresent {
		t.Fatalf("captured login state mismatch: %+v", state)
	}
	stored := f.load("new")
	if !bytes.Equal(stored.Credentials, credentials) || !bytes.Equal(stored.Telemetry, telemetry) {
		t.Fatal("captured login profile mismatch")
	}
	registry, err := f.app.Store.Registry()
	if err != nil {
		t.Fatal(err)
	}
	if registry.ActiveProfile != "new" || registry.PreviousProfile != "" {
		t.Fatalf("login registry = %+v", registry)
	}
	if _, err := os.Stat(f.app.coordinatorPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("coordinator remains after successful login: %v", err)
	}
}

func TestCoordinatorRecoveryCommitsOnlyExactTargetState(t *testing.T) {
	f := newCommandFixture(t)
	aCredentials := commandCredentials("account-a", "token-a")
	bCredentials := commandCredentials("account-b", "token-b")
	f.writeLive(aCredentials, []byte(`{"deviceMid":"a"}`), true)
	if err := f.app.Save("a", false); err != nil {
		t.Fatal(err)
	}
	f.writeLive(bCredentials, []byte(`{"deviceMid":"b"}`), true)
	if err := f.app.Save("b", false); err != nil {
		t.Fatal(err)
	}
	f.writeLive(aCredentials, []byte(`{"deviceMid":"a"}`), true)
	oldAlias, oldBundle, oldPresent, err := f.app.syncLive(true)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := f.app.createBackup(transaction.Automatic, "test recovery", oldAlias, oldBundle, oldPresent)
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.app.beginCoordinator("switch", "b", backup.ID)
	if err != nil {
		t.Fatal(err)
	}
	target := f.load("b")
	record.TargetStateRecorded = true
	record.TargetCredentialsPresent = true
	record.TargetTelemetryPresent = true
	record.TargetCredentialsSHA = checksumBytes(target.Credentials)
	record.TargetTelemetrySHA = checksumBytes(target.Telemetry)
	if err := writeCoordinator(f.app.coordinatorPath(), record); err != nil {
		t.Fatal(err)
	}
	if err := f.app.Engine.Apply(target); err != nil {
		t.Fatal(err)
	}
	if err := f.app.markCoordinatorLive(record); err != nil {
		t.Fatal(err)
	}
	// List invokes recovery. It must recognize the exact target and commit the
	// registry, including the previous pointer, without printing secrets.
	var output bytes.Buffer
	f.app.Out = &output
	if err := f.app.List(false); err != nil {
		t.Fatal(err)
	}
	registry, err := f.app.Store.Registry()
	if err != nil {
		t.Fatal(err)
	}
	if registry.ActiveProfile != "b" || registry.PreviousProfile != "a" {
		t.Fatalf("registry after coordinator recovery = %+v", registry)
	}
	if _, err := os.Stat(f.app.coordinatorPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("coordinator journal remains: %v", err)
	}
	if strings.Contains(output.String(), "token-") || strings.Contains(output.String(), "deviceMid") {
		t.Fatal("list output leaked credential or telemetry material")
	}
}

func TestJSONOutputRedactsCredentialAndTelemetryValues(t *testing.T) {
	f := newCommandFixture(t)
	f.writeLive(commandCredentials("account-a", "access-secret"), []byte(`{"deviceMid":"telemetry-secret"}`), true)
	if err := f.app.Save("work", false); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	f.app.Out = &output
	if err := f.app.Execute(context.Background(), []string{"list", "--json"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "access-secret") || strings.Contains(output.String(), "telemetry-secret") {
		t.Fatalf("JSON output leaked secrets: %s", output.String())
	}
	output.Reset()
	if err := f.app.Execute(context.Background(), []string{"current", "--json"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "access-secret") || strings.Contains(output.String(), "telemetry-secret") {
		t.Fatalf("current JSON leaked secrets: %s", output.String())
	}
}

func TestManualBackupSurvivesAutomaticRotationAndRestoreRotatesTelemetry(t *testing.T) {
	f := newCommandFixture(t)
	originalCredentials := commandCredentials("account-a", "token-original")
	originalTelemetry := []byte(`{"deviceMid":"telemetry-original"}`)
	f.writeLive(originalCredentials, originalTelemetry, true)
	if err := f.app.Save("a", false); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	f.app.Out = &output
	if err := f.app.Backup(); err != nil {
		t.Fatal(err)
	}
	manualID := strings.TrimSpace(output.String())
	if manualID == "" {
		t.Fatal("manual backup did not return an ID")
	}
	for i := 0; i < 4; i++ {
		if _, err := f.app.createBackup(transaction.Automatic, "rotation", "a", model.SessionBundle{Credentials: commandCredentials("account-a", fmt.Sprintf("auto-%d", i)), TelemetryPresent: false}, true); err != nil {
			t.Fatal(err)
		}
	}
	backups, err := f.app.Backups.List()
	if err != nil {
		t.Fatal(err)
	}
	automatic, manual := 0, 0
	for _, backup := range backups {
		if backup.Kind == transaction.Automatic {
			automatic++
		}
		if backup.Kind == transaction.Manual && backup.ID == manualID {
			manual++
		}
	}
	if automatic != 2 || manual != 1 {
		t.Fatalf("backup rotation automatic=%d manual=%d all=%+v", automatic, manual, backups)
	}
	f.writeLive(commandCredentials("account-a", "token-current"), []byte(`{"deviceMid":"telemetry-current"}`), true)
	output.Reset()
	if err := f.app.Restore(manualID); err != nil {
		t.Fatal(err)
	}
	state, err := zcode.ReadState(f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.Credentials, originalCredentials) || !bytes.Equal(state.Telemetry, originalTelemetry) || !state.TelemetryPresent {
		t.Fatalf("restored state mismatch: %+v", state)
	}
}

func TestTelemetryOnlyBackupRestoresWithoutInventingCredentials(t *testing.T) {
	f := newCommandFixture(t)
	telemetry := []byte(`{"deviceMid":"orphaned-telemetry"}`)
	if err := zcode.WriteTelemetry(f.paths.TelemetryPath, telemetry); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	f.app.Out = &output
	if err := f.app.Backup(); err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(output.String())
	if id == "" {
		t.Fatal("telemetry-only backup did not return an ID")
	}
	if err := f.app.Logout(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.paths.TelemetryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("logout left telemetry behind: %v", err)
	}
	if err := f.app.Restore(id); err != nil {
		t.Fatal(err)
	}
	state, err := zcode.ReadTelemetry(f.paths.TelemetryPath)
	if err != nil || !bytes.Equal(state, telemetry) {
		t.Fatalf("telemetry-only restore = %q err=%v", state, err)
	}
	if _, err := os.Stat(f.paths.CredentialsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("telemetry-only restore invented credentials: %v", err)
	}
}

func TestDoctorRepairCleansKnownTemporaryFilesWithoutTouchingLiveFiles(t *testing.T) {
	f := newCommandFixture(t)
	orphan := filepath.Join(f.app.Config.DataDir, ".coordinator-orphan")
	if err := os.WriteFile(orphan, []byte("temporary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.app.Config.DataDir, "keep.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.app.Doctor(true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("doctor left known temporary file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.app.Config.DataDir, "keep.txt")); err != nil {
		t.Fatalf("doctor removed unrelated file: %v", err)
	}
}

func TestDoctorRepairRefusesBeforeMutationWhenZCodeRuns(t *testing.T) {
	f := newCommandFixture(t)
	orphan := filepath.Join(f.app.Config.DataDir, ".coordinator-orphan")
	if err := os.WriteFile(orphan, []byte("temporary"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.state[1] = true
	if err := f.app.Doctor(true, true); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("Doctor error = %v", err)
	}
	info, err := os.Stat(orphan)
	if err != nil {
		t.Fatalf("repair mutated temporary file before refusing: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("repair changed mode before refusing: %04o", info.Mode().Perm())
	}
}

func TestDoctorWithoutRepairLeavesPendingProfileJournalUntouched(t *testing.T) {
	f := newCommandFixture(t)
	journal := filepath.Join(f.app.Config.DataDir, "profile.journal")
	contents := []byte(`{"pending":true}`)
	if err := os.WriteFile(journal, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	f.app.Out = &out
	if err := f.app.Doctor(false, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(journal)
	if err != nil || !bytes.Equal(got, contents) {
		t.Fatalf("plain doctor changed pending journal: %q err=%v", got, err)
	}
	if !strings.Contains(out.String(), "run doctor --repair") {
		t.Fatalf("doctor did not report deferred recovery: %s", out.String())
	}
}

func TestDoctorReturnsUnhealthyExitAfterWritingDiagnostics(t *testing.T) {
	f := newCommandFixture(t)
	if err := os.Remove(f.paths.Executable); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	f.app.Out = &out
	if err := f.app.Doctor(false, true); !errors.Is(err, ErrDoctorUnhealthy) {
		t.Fatalf("Doctor error = %v, want ErrDoctorUnhealthy", err)
	}
	if !strings.Contains(out.String(), `"name": "ZCode installation"`) || !strings.Contains(out.String(), `"status": "ERROR"`) {
		t.Fatalf("doctor did not write diagnostics before returning error: %s", out.String())
	}
}

func TestLoginFromTelemetryOnlyStateDoesNotRewriteWhileRunning(t *testing.T) {
	f := newCommandFixture(t)
	if err := os.MkdirAll(f.paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := zcode.WriteTelemetry(f.paths.TelemetryPath, []byte(`{"deviceMid":"old"}`)); err != nil {
		t.Fatal(err)
	}
	credentials := commandCredentials("account-new", "token-new")
	telemetry := []byte(`{"deviceMid":"new"}`)
	f.app.WaitAuth = func(context.Context, zcode.WatchOptions) (model.SessionBundle, error) {
		f.writeLive(credentials, telemetry, true)
		if err := os.Chmod(f.paths.CredentialsPath, 0o640); err != nil {
			t.Fatal(err)
		}
		return model.SessionBundle{Credentials: credentials, Telemetry: telemetry, TelemetryPresent: true}, nil
	}
	if err := f.app.Login(context.Background(), "new"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f.paths.CredentialsPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("login rewrote live credentials while ZCode ran; mode=%04o", info.Mode().Perm())
	}
}

func TestRestoreAllowsAuthenticatedUnmanagedBackup(t *testing.T) {
	f := newCommandFixture(t)
	credentials := commandCredentials("account-unmanaged", "token-u")
	f.writeLive(credentials, []byte(`{"deviceMid":"u"}`), true)
	var out bytes.Buffer
	f.app.Out = &out
	if err := f.app.Backup(); err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(out.String())
	if err := f.app.Logout(); err != nil {
		t.Fatal(err)
	}
	if err := f.app.Restore(id); err != nil {
		t.Fatal(err)
	}
	state, err := zcode.ReadState(f.paths)
	if err != nil || !bytes.Equal(state.Credentials, credentials) || !state.TelemetryPresent {
		t.Fatalf("unmanaged restore state=%+v err=%v", state, err)
	}
	registry, err := f.app.Store.Registry()
	if err != nil || registry.ActiveProfile != "" {
		t.Fatalf("unmanaged restore active profile=%q err=%v", registry.ActiveProfile, err)
	}
}

func TestSwitchFlagMayFollowAlias(t *testing.T) {
	f := newCommandFixture(t)
	credentials := commandCredentials("account-a", "token-a")
	f.writeLive(credentials, nil, false)
	if err := f.app.Save("a", false); err != nil {
		t.Fatal(err)
	}
	if err := f.app.Execute(context.Background(), []string{"switch", "a", "--restart"}); err != nil {
		t.Fatal(err)
	}
}

func TestRestartSwitchRestartsAfterPostStopFailure(t *testing.T) {
	f := newCommandFixture(t)
	f.writeLive(commandCredentials("account-b", "token-b"), nil, false)
	if err := f.app.Save("b", false); err != nil {
		t.Fatal(err)
	}
	// The target is valid, but the currently live account is unmanaged.  The
	// switch must fail without leaving the desktop stopped after SIGTERM.
	f.writeLive(commandCredentials("account-unmanaged", "token-current"), nil, false)
	f.state[1] = true
	err := f.app.Switch(context.Background(), "b", true)
	if !errors.Is(err, ErrUnmanagedState) {
		t.Fatalf("Switch error = %v, want ErrUnmanagedState", err)
	}
	if !f.state[1] {
		t.Fatal("restart-mode failure left ZCode stopped")
	}
}
