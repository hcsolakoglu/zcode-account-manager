package profile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hcsolakoglu/zcode-account-manager/internal/model"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	key := []byte("01234567890123456789012345678901")
	store, err := NewStoreWithKey(t.TempDir(), key)
	if err != nil {
		t.Fatalf("NewStoreWithKey: %v", err)
	}
	return store
}

func testEncryptedBlob(t *testing.T, store *Store, id string, identity model.Identity, bundle model.SessionBundle) []byte {
	t.Helper()
	key, err := store.masterKey()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := encryptProfile(id, identity, bundle, key)
	clearBytes(key)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func writeInterruptedProfileState(t *testing.T, store *Store, record profileJournal, newBlob, newRegistry []byte) {
	t.Helper()
	if err := store.writeJournalLocked(record); err != nil {
		t.Fatal(err)
	}
	if err := secureWriteFile(record.ProfilePath, newBlob); err != nil {
		t.Fatal(err)
	}
	if err := secureWriteFile(record.RegistryPath, newRegistry); err != nil {
		t.Fatal(err)
	}
}

func TestSaveLoadRotatesCredentialAndTelemetryAsOneBundle(t *testing.T) {
	store := testStore(t)
	credentials := []byte(`{"access_token":"access-secret","refresh_token":"refresh-secret","unknown":{"future":true}}`)
	telemetry := []byte(`{"device_id":"telemetry-secret","future_field":[1,2,3]}`)
	metadata, err := store.Save("work", model.Identity{AccountID: "acct-1", Provider: "zai"}, model.SessionBundle{
		Credentials:      credentials,
		Telemetry:        telemetry,
		TelemetryPresent: true,
	})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if metadata.ProfileID == "" || !metadata.HasTelemetry {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	profile, err := store.Load("work")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(profile.Bundle.Credentials) != string(credentials) {
		t.Fatalf("credentials changed: got %q", profile.Bundle.Credentials)
	}
	if string(profile.Bundle.Telemetry) != string(telemetry) {
		t.Fatalf("telemetry changed: got %q", profile.Bundle.Telemetry)
	}

	registryBytes, err := os.ReadFile(store.registryPath())
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	if strings.Contains(string(registryBytes), "access-secret") || strings.Contains(string(registryBytes), "telemetry-secret") {
		t.Fatal("registry contains secret payload")
	}
	profileBytes, err := os.ReadFile(store.profilePath(metadata.ProfileID))
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	if strings.Contains(string(profileBytes), "access-secret") || strings.Contains(string(profileBytes), "telemetry-secret") {
		t.Fatal("encrypted profile contains plaintext secret")
	}
	if info, err := os.Stat(store.root); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("root permissions: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(store.registryPath()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("registry permissions: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(store.profilePath(metadata.ProfileID)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("profile permissions: info=%v err=%v", info, err)
	}
}

func TestSavePreservesImmutableIDAndRejectsDuplicateIdentity(t *testing.T) {
	store := testStore(t)
	identity := model.Identity{AccountID: "acct-1", Provider: "zai"}
	first, err := store.Save("work", identity, model.SessionBundle{Credentials: []byte(`{"v":1}`)})
	if err != nil {
		t.Fatalf("first Save: %v", err)
	}
	second, err := store.Save("work", identity, model.SessionBundle{Credentials: []byte(`{"v":2}`)})
	if err != nil {
		t.Fatalf("second Save: %v", err)
	}
	if second.ProfileID != first.ProfileID {
		t.Fatalf("profile ID changed: %q -> %q", first.ProfileID, second.ProfileID)
	}
	if _, err := store.Save("personal", identity, model.SessionBundle{Credentials: []byte(`{"v":3}`)}); !errors.Is(err, ErrDuplicateIdentity) {
		t.Fatalf("duplicate identity error = %v", err)
	}
	if _, err := store.Save("work", model.Identity{AccountID: "acct-2", Provider: "zai"}, model.SessionBundle{Credentials: []byte(`{"v":4}`)}); !errors.Is(err, ErrAliasIdentityMismatch) {
		t.Fatalf("alias mismatch error = %v", err)
	}
}

func TestSaveRejectsIdentityControlCharacters(t *testing.T) {
	store := testStore(t)
	if _, err := store.Save("work", model.Identity{AccountID: "acct\n1", Provider: "zai"}, model.SessionBundle{Credentials: []byte(`{"v":1}`)}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("control-character identity error = %v", err)
	}
}

func TestInterruptedNewSaveRecoversOldRegistryWithoutOrphan(t *testing.T) {
	root := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	store, err := NewStoreWithKey(root, key)
	if err != nil {
		t.Fatal(err)
	}
	keepIdentity := model.Identity{AccountID: "acct-keep", Provider: "zai"}
	keepBundle := model.SessionBundle{Credentials: []byte(`{"access_token":"keep-token"}`)}
	keepMetadata, err := store.Save("keep", keepIdentity, keepBundle)
	if err != nil {
		t.Fatal(err)
	}
	oldRegistry, registryPresent, err := store.registrySnapshotLocked()
	if err != nil || !registryPresent {
		t.Fatalf("old registry present=%v err=%v", registryPresent, err)
	}
	newIdentity := model.Identity{AccountID: "acct-new", Provider: "zai"}
	newID := "interrupted-new"
	newBundle := model.SessionBundle{Credentials: []byte(`{"access_token":"new-token"}`)}
	newBlob := testEncryptedBlob(t, store, newID, newIdentity, newBundle)
	targetRegistry, err := store.Registry()
	if err != nil {
		t.Fatal(err)
	}
	targetRegistry.Profiles = cloneProfiles(targetRegistry.Profiles)
	targetRegistry.Profiles["new"] = model.ProfileMetadata{
		ProfileID: newID, AccountID: newIdentity.AccountID, Provider: newIdentity.Provider,
		LastSynced: time.Unix(1700000100, 0).UTC(),
	}
	targetRegistryBytes, err := encodeRegistry(targetRegistry)
	if err != nil {
		t.Fatal(err)
	}
	record := profileJournal{
		SchemaVersion: profileJournalSchemaVersion, Operation: "save", Phase: profileJournalPrepared,
		RegistryPath: store.registryPath(), ProfilePath: store.profilePath(newID),
		RegistryPresent: true, OldRegistry: oldRegistry,
	}
	writeInterruptedProfileState(t, store, record, newBlob, targetRegistryBytes)
	journalBytes, err := os.ReadFile(store.journalPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(journalBytes, []byte("new-token")) {
		t.Fatal("profile journal contains plaintext new credentials")
	}

	recovered, err := NewStoreWithKey(root, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(store.journalPath()); err != nil {
		t.Fatalf("store construction recovered before caller lock: %v", err)
	}
	if _, err := recovered.Load("new"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("interrupted new profile remains registered: %v", err)
	}
	loaded, err := recovered.Load("keep")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.Bundle.Credentials, keepBundle.Credentials) || loaded.Metadata.ProfileID != keepMetadata.ProfileID {
		t.Fatalf("old profile changed after recovery: %+v", loaded)
	}
	if _, err := os.Lstat(store.profilePath(newID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan new profile after recovery: %v", err)
	}
	if _, err := os.Lstat(store.journalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("profile journal remains after recovery: %v", err)
	}
}

func TestRegistryRejectsDuplicateJSONKeys(t *testing.T) {
	root := t.TempDir()
	store, err := NewStoreWithKey(root, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	duplicate := []byte(`{"schema_version":1,"schema_version":1,"active_profile":"","previous_profile":"","profiles":{}}`)
	if err := os.WriteFile(store.registryPath(), duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Registry(); err == nil || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Registry error = %v, want ErrCorrupt", err)
	}
}

func TestInterruptedRefreshSaveRecoversOldEncryptedBundle(t *testing.T) {
	root := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	store, err := NewStoreWithKey(root, key)
	if err != nil {
		t.Fatal(err)
	}
	identity := model.Identity{AccountID: "acct-refresh", Provider: "zai"}
	oldBundle := model.SessionBundle{
		Credentials: []byte(`{"access_token":"old-token","future":{"v":1}}`),
		Telemetry:   []byte(`{"deviceMid":"old-device","future":true}`), TelemetryPresent: true,
	}
	metadata, err := store.Save("work", identity, oldBundle)
	if err != nil {
		t.Fatal(err)
	}
	oldRegistry, registryPresent, err := store.registrySnapshotLocked()
	if err != nil || !registryPresent {
		t.Fatalf("old registry present=%v err=%v", registryPresent, err)
	}
	oldProfile, err := os.ReadFile(store.profilePath(metadata.ProfileID))
	if err != nil {
		t.Fatal(err)
	}
	newBundle := model.SessionBundle{
		Credentials: []byte(`{"access_token":"refreshed-token","future":{"v":2}}`),
		Telemetry:   []byte(`{"deviceMid":"refreshed-device","future":true}`), TelemetryPresent: true,
	}
	newBlob := testEncryptedBlob(t, store, metadata.ProfileID, identity, newBundle)
	targetRegistry, err := store.Registry()
	if err != nil {
		t.Fatal(err)
	}
	targetRegistry.Profiles = cloneProfiles(targetRegistry.Profiles)
	targetMetadata := targetRegistry.Profiles["work"]
	targetMetadata.LastSynced = time.Unix(1700000200, 0).UTC()
	targetRegistry.Profiles["work"] = targetMetadata
	targetRegistryBytes, err := encodeRegistry(targetRegistry)
	if err != nil {
		t.Fatal(err)
	}
	record := profileJournal{
		SchemaVersion: profileJournalSchemaVersion, Operation: "save", Phase: profileJournalPrepared,
		RegistryPath: store.registryPath(), ProfilePath: store.profilePath(metadata.ProfileID),
		RegistryPresent: true, OldRegistry: oldRegistry, ProfilePresent: true, OldProfile: oldProfile,
	}
	writeInterruptedProfileState(t, store, record, newBlob, targetRegistryBytes)
	journalBytes, err := os.ReadFile(store.journalPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"old-token", "old-device", "refreshed-token", "refreshed-device"} {
		if bytes.Contains(journalBytes, []byte(secret)) {
			t.Fatalf("profile journal contains plaintext secret %q", secret)
		}
	}

	recovered, err := NewStoreWithKey(root, key)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := recovered.Load("work")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.Bundle.Credentials, oldBundle.Credentials) || !bytes.Equal(loaded.Bundle.Telemetry, oldBundle.Telemetry) || loaded.Metadata.LastSynced != metadata.LastSynced {
		t.Fatalf("refresh recovery did not restore old bundle: %+v", loaded)
	}
	if _, err := os.Lstat(store.journalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("profile journal remains after refresh recovery: %v", err)
	}
}

func TestCommittedProfileJournalPreservesNewBundle(t *testing.T) {
	root := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	store, err := NewStoreWithKey(root, key)
	if err != nil {
		t.Fatal(err)
	}
	identity := model.Identity{AccountID: "acct-commit", Provider: "zai"}
	oldBundle := model.SessionBundle{Credentials: []byte(`{"access_token":"commit-old"}`)}
	metadata, err := store.Save("work", identity, oldBundle)
	if err != nil {
		t.Fatal(err)
	}
	oldRegistry, _, err := store.registrySnapshotLocked()
	if err != nil {
		t.Fatal(err)
	}
	oldProfile, err := os.ReadFile(store.profilePath(metadata.ProfileID))
	if err != nil {
		t.Fatal(err)
	}
	newBundle := model.SessionBundle{Credentials: []byte(`{"access_token":"commit-new"}`)}
	newBlob := testEncryptedBlob(t, store, metadata.ProfileID, identity, newBundle)
	targetRegistry, err := store.Registry()
	if err != nil {
		t.Fatal(err)
	}
	targetRegistry.Profiles = cloneProfiles(targetRegistry.Profiles)
	targetRegistry.Profiles["work"] = metadata
	targetRegistryBytes, err := encodeRegistry(targetRegistry)
	if err != nil {
		t.Fatal(err)
	}
	record := profileJournal{
		SchemaVersion: profileJournalSchemaVersion, Operation: "save", Phase: profileJournalPrepared,
		RegistryPath: store.registryPath(), ProfilePath: store.profilePath(metadata.ProfileID),
		RegistryPresent: true, OldRegistry: oldRegistry, ProfilePresent: true, OldProfile: oldProfile,
	}
	writeInterruptedProfileState(t, store, record, newBlob, targetRegistryBytes)
	record.Phase = profileJournalCommitted
	if err := store.writeJournalLocked(record); err != nil {
		t.Fatal(err)
	}

	recovered, err := NewStoreWithKey(root, key)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := recovered.Load("work")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.Bundle.Credentials, newBundle.Credentials) {
		t.Fatalf("committed journal rolled back new profile: %q", loaded.Bundle.Credentials)
	}
	if _, err := os.Lstat(store.journalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed profile journal remains: %v", err)
	}
}

func TestInterruptedRemoveRecoversRegistryAndProfile(t *testing.T) {
	root := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	store, err := NewStoreWithKey(root, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save("keep", model.Identity{AccountID: "acct-keep", Provider: "zai"}, model.SessionBundle{Credentials: []byte(`{"access_token":"keep"}`)}); err != nil {
		t.Fatal(err)
	}
	removeMetadata, err := store.Save("remove", model.Identity{AccountID: "acct-remove", Provider: "zai"}, model.SessionBundle{Credentials: []byte(`{"access_token":"remove"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetActive("remove"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActive("keep"); err != nil {
		t.Fatal(err)
	}
	oldRegistry, registryPresent, err := store.registrySnapshotLocked()
	if err != nil || !registryPresent {
		t.Fatalf("old registry present=%v err=%v", registryPresent, err)
	}
	oldProfile, err := os.ReadFile(store.profilePath(removeMetadata.ProfileID))
	if err != nil {
		t.Fatal(err)
	}
	targetRegistry, err := store.Registry()
	if err != nil {
		t.Fatal(err)
	}
	targetRegistry.Profiles = cloneProfiles(targetRegistry.Profiles)
	delete(targetRegistry.Profiles, "remove")
	targetRegistry.PreviousProfile = ""
	targetRegistryBytes, err := encodeRegistry(targetRegistry)
	if err != nil {
		t.Fatal(err)
	}
	record := profileJournal{
		SchemaVersion: profileJournalSchemaVersion, Operation: "remove", Phase: profileJournalPrepared,
		RegistryPath: store.registryPath(), ProfilePath: store.profilePath(removeMetadata.ProfileID),
		RegistryPresent: true, OldRegistry: oldRegistry, ProfilePresent: true, OldProfile: oldProfile,
	}
	if err := store.writeJournalLocked(record); err != nil {
		t.Fatal(err)
	}
	if err := secureWriteFile(record.RegistryPath, targetRegistryBytes); err != nil {
		t.Fatal(err)
	}
	if err := secureRemoveFile(record.ProfilePath); err != nil {
		t.Fatal(err)
	}

	recovered, err := NewStoreWithKey(root, key)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := recovered.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("recovered profile count = %d, want 2", len(entries))
	}
	if _, err := recovered.Load("remove"); err != nil {
		t.Fatalf("removed profile not restored: %v", err)
	}
	registry, err := recovered.Registry()
	if err != nil {
		t.Fatal(err)
	}
	if registry.ActiveProfile != "keep" || registry.PreviousProfile != "remove" {
		t.Fatalf("old active pointers not restored: %+v", registry)
	}
	if _, err := os.Lstat(store.journalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("profile journal remains after remove recovery: %v", err)
	}
}

func TestTelemetryPresenceIsExplicitAndEmptyTelemetryStillRotates(t *testing.T) {
	store := testStore(t)
	identity := model.Identity{AccountID: "acct-1", Provider: "zai"}
	if _, err := store.Save("invalid", identity, model.SessionBundle{
		Credentials: []byte(`{"v":1}`),
		Telemetry:   []byte(`{"present":true}`),
	}); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("nonempty telemetry without presence error = %v", err)
	}
	metadata, err := store.Save("work", identity, model.SessionBundle{
		Credentials:      []byte(`{"v":1}`),
		TelemetryPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !metadata.HasTelemetry {
		t.Fatalf("empty but present telemetry metadata: %+v", metadata)
	}
	loaded, err := store.Load("work")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Bundle.TelemetryPresent || len(loaded.Bundle.Telemetry) != 0 {
		t.Fatalf("loaded telemetry state: %+v", loaded.Bundle)
	}
}

func TestWrongKeyAndTamperingAreAuthenticationErrors(t *testing.T) {
	root := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	store, err := NewStoreWithKey(root, key)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := store.Save("work", model.Identity{AccountID: "acct-1", Provider: "zai"}, model.SessionBundle{Credentials: []byte(`{"token":"secret"}`)})
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := []byte("abcdefghijklmnopqrstuvwxyzABCDEF")
	wrong, err := NewStoreWithKey(root, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Load("work"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key error = %v", err)
	}
	blobPath := filepath.Join(root, profilesDirName, profileFileName(metadata.ProfileID))
	blob, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 1
	if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("work"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered profile error = %v", err)
	}
}

func TestCorruptionSymlinkAndOrphanAreNotSilentlyIgnored(t *testing.T) {
	store := testStore(t)
	metadata, err := store.Save("work", model.Identity{AccountID: "acct-1", Provider: "zai"}, model.SessionBundle{Credentials: []byte(`{"v":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	profilePath := store.profilePath(metadata.ProfileID)
	backupPath := filepath.Join(store.root, "saved-profile")
	if err := os.Rename(profilePath, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backupPath, profilePath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("work"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink load error = %v", err)
	}
	if _, err := store.List(); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink list error = %v", err)
	}
	if err := os.Remove(profilePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backupPath, profilePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.profilesDir, "orphan.enc"), []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(); !errors.Is(err, ErrOrphanedProfile) {
		t.Fatalf("orphan list error = %v", err)
	}
}

func TestRemoveIsExplicitAndLeavesNoRegisteredOrphan(t *testing.T) {
	store := testStore(t)
	if err := store.Remove("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing remove error = %v", err)
	}
	metadata, err := store.Save("work", model.Identity{AccountID: "acct-1", Provider: "zai"}, model.SessionBundle{Credentials: []byte(`{"v":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("work"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(store.profilePath(metadata.ProfileID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("profile still exists: %v", err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatalf("List after remove: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries after remove: %+v", entries)
	}
	if _, err := store.Load("work"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("load after remove error = %v", err)
	}
}

func TestActivePointersAreRegistryOnly(t *testing.T) {
	store := testStore(t)
	if _, err := store.Save("work", model.Identity{AccountID: "acct-1", Provider: "zai"}, model.SessionBundle{Credentials: []byte(`{"v":1}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save("personal", model.Identity{AccountID: "acct-2", Provider: "zai"}, model.SessionBundle{Credentials: []byte(`{"v":2}`)}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActive("work"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActive("personal"); err != nil {
		t.Fatal(err)
	}
	registry, err := store.Registry()
	if err != nil {
		t.Fatal(err)
	}
	if registry.ActiveProfile != "personal" || registry.PreviousProfile != "work" {
		t.Fatalf("active pointers: %+v", registry)
	}
}
