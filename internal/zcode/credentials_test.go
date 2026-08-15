package zcode

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hcsolakoglu/zcode-account-manager/internal/model"
)

func TestValidateCredentialsRejectsDuplicateKeys(t *testing.T) {
	if err := ValidateCredentials([]byte(`{"token":"first","token":"second"}`)); err == nil {
		t.Fatal("duplicate credential key unexpectedly accepted")
	}
}

func TestEncryptedZCodeStoreIdentityAndAuthentication(t *testing.T) {
	cipher := NewCredentialCipherWithSecret("fixture-secret")
	provider, err := cipher.EncryptCredentialValue("zai")
	if err != nil {
		t.Fatal(err)
	}
	info, err := cipher.EncryptCredentialValue(`{"id":"acct-123","user_id":"acct-123","email":"private@example.invalid"}`)
	if err != nil {
		t.Fatal(err)
	}
	token, err := cipher.EncryptCredentialValue("opaque-token")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"oauth:active_provider":` + quote(provider) + `,"oauth:zai:user_info":` + quote(info) + `,"oauth:zai:access_token":` + quote(token) + `,"new:future_field":"survive"}`)

	identity, err := cipher.IdentityFromCredentials(data)
	if err != nil {
		t.Fatal(err)
	}
	if identity.AccountID != "acct-123" || identity.Provider != "zai" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	authenticated, err := cipher.Authenticated(data)
	if err != nil || !authenticated {
		t.Fatalf("authenticated=%v err=%v", authenticated, err)
	}
}

func TestPlaintextIdentityVariants(t *testing.T) {
	fixtures := [][]byte{
		[]byte(`{"provider":"zai","account":{"id":"acct-a"},"access_token":"a","unknown":{"keep":true}}`),
		[]byte(`{"providerId":"zai","user":{"user_id":"acct-b"},"refreshToken":"b"}`),
		[]byte(`{"provider":"zai","identity":{"sub":"acct-c"},"authenticated":true}`),
	}
	want := []string{"acct-a", "acct-b", "acct-c"}
	for index, fixture := range fixtures {
		identity, err := IdentityFromCredentials(fixture)
		if err != nil {
			t.Fatalf("fixture %d: %v", index, err)
		}
		if identity.AccountID != want[index] || identity.Provider != "zai" {
			t.Fatalf("fixture %d: %#v", index, identity)
		}
		if !IsAuthenticated(fixture) {
			t.Fatalf("fixture %d not authenticated", index)
		}
	}
}

func TestIdentityConflictAndSafeDecryptError(t *testing.T) {
	_, err := IdentityFromCredentials([]byte(`{"provider":"zai","user":{"id":"a","user_id":"b"},"token":"x"}`))
	if !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("expected identity conflict, got %v", err)
	}
	_, err = NewCredentialCipherWithSecret("fixture-secret").IdentityFromCredentials([]byte(`{"oauth:active_provider":"enc:v2:unsupported","oauth:zai:user_info":"{}"}`))
	if !errors.Is(err, ErrCredentialDecrypt) {
		t.Fatalf("expected safe decrypt error, got %v", err)
	}
	if len(err.Error()) > 128 {
		t.Fatalf("decrypt error unexpectedly verbose: %q", err)
	}
}

func TestStateOpaqueRoundTripAndTelemetryPresence(t *testing.T) {
	dir := t.TempDir()
	paths := PathsForStateDir(filepath.Join(dir, "v2"))
	credentials := []byte("{\n  \"unknown\": [1, 2, 3],\n  \"oauth:active_provider\": \"zai\"\n}\n")
	telemetry := []byte("{\"deviceMid\":\"opaque\",\"newField\":true}\n")
	if err := WriteState(paths, model.SessionBundle{Credentials: credentials, Telemetry: telemetry, TelemetryPresent: true}); err != nil {
		t.Fatal(err)
	}
	state, err := ReadState(paths)
	if err != nil {
		t.Fatal(err)
	}
	if string(state.Credentials) != string(credentials) || string(state.Telemetry) != string(telemetry) || !state.TelemetryPresent {
		t.Fatalf("opaque state changed: %#v", state)
	}
	if mode := fileMode(t, paths.CredentialsPath); mode.Perm() != 0o600 {
		t.Fatalf("credentials mode = %o", mode.Perm())
	}
	if err := ClearTelemetry(paths.TelemetryPath); err != nil {
		t.Fatal(err)
	}
	cleared, err := ReadTelemetry(paths.TelemetryPath)
	if err != nil || string(cleared) != "{}" {
		t.Fatalf("telemetry clear: %q %v", cleared, err)
	}
}

func TestStateRejectsSymlinkAndNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	paths := PathsForStateDir(dir)
	if err := os.WriteFile(filepath.Join(dir, "real.json"), []byte(`{"token":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real.json"), paths.CredentialsPath); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(paths.CredentialsPath); !errors.Is(err, ErrUnsafeStatePath) {
		t.Fatalf("symlink error = %v", err)
	}
	if err := os.Remove(paths.CredentialsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.CredentialsPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(paths.CredentialsPath); !errors.Is(err, ErrUnsafeStatePath) {
		t.Fatalf("directory error = %v", err)
	}
}

func TestWaitForAuthenticatedPollsBoundedly(t *testing.T) {
	dir := t.TempDir()
	paths := PathsForStateDir(dir)
	if err := os.WriteFile(paths.CredentialsPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = WriteTelemetry(paths.TelemetryPath, []byte(`{"deviceMid":"watch"}`))
		_ = WriteCredentials(paths.CredentialsPath, []byte(`{"provider":"zai","account_id":"acct-watch","access_token":"token"}`))
	}()
	state, err := NewAdapter(paths).WaitForAuthenticated(context.Background(), WatchOptions{Interval: 5 * time.Millisecond, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !state.TelemetryPresent || string(state.Telemetry) != `{"deviceMid":"watch"}` {
		t.Fatalf("watch state: %#v", state)
	}
}

func TestWaitForAuthenticatedRequiresStableBundle(t *testing.T) {
	dir := t.TempDir()
	paths := PathsForStateDir(dir)
	credentials := []byte(`{"provider":"zai","account_id":"acct-watch","access_token":"token"}`)
	if err := WriteState(paths, model.SessionBundle{Credentials: credentials, Telemetry: []byte(`{"deviceMid":"first"}`), TelemetryPresent: true}); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(5 * time.Millisecond)
		_ = WriteTelemetry(paths.TelemetryPath, []byte(`{"deviceMid":"second"}`))
	}()
	state, err := NewAdapter(paths).WaitForAuthenticated(context.Background(), WatchOptions{Interval: 15 * time.Millisecond, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if string(state.Telemetry) != `{"deviceMid":"second"}` {
		t.Fatalf("watcher returned unstable first observation: %s", state.Telemetry)
	}
}

func quote(value string) string {
	return `"` + value + `"`
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}
