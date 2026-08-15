package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hcsolakoglu/zcode-account-manager/internal/model"
)

const (
	registryFileName       = "registry.json"
	profilesDirName        = "profiles"
	profileJournalFileName = "profile.journal"
)

const profileJournalSchemaVersion = 1

const (
	profileJournalPrepared  = "prepared"
	profileJournalCommitted = "committed"
)

// profileJournal stores only the pre-operation registry metadata and the old
// encrypted profile blob.  It never contains decrypted credentials or
// telemetry.  A prepared journal means recovery must restore the old state;
// a committed journal means both destination writes completed and recovery
// only needs to remove the journal.
type profileJournal struct {
	SchemaVersion int    `json:"schema_version"`
	Operation     string `json:"operation"`
	Phase         string `json:"phase"`
	RegistryPath  string `json:"registry_path"`
	ProfilePath   string `json:"profile_path"`

	RegistryPresent bool   `json:"registry_present"`
	OldRegistry     []byte `json:"old_registry,omitempty"`
	ProfilePresent  bool   `json:"profile_present"`
	OldProfile      []byte `json:"old_profile,omitempty"`
}

// Store is the encrypted profile repository. It owns only the profile-store
// directory and never reads or writes ZCode's live state. The transaction
// layer can hold its process-wide auth lock around calls to Store methods.
type Store struct {
	root        string
	profilesDir string
	keys        KeyProvider
	now         func() time.Time
	newID       func() (string, error)
	mu          sync.Mutex
}

// Entry is a registry alias and its non-secret metadata. The encrypted
// SessionBundle is intentionally not included in list results.
type Entry struct {
	Alias    string
	Metadata model.ProfileMetadata
}

// Profile is the result of loading a profile. Bundle contains both the
// credentials document and telemetry-state.json document; callers should treat
// the two fields as one indivisible state bundle during account switching.
type Profile struct {
	Alias    string
	Metadata model.ProfileMetadata
	Bundle   model.SessionBundle
}

// NewStore prepares root and its profiles subdirectory. If keys is nil, the
// native platform secure provider is used (Secret Service, Keychain, or
// DPAPI). Tests should inject a StaticKeyProvider or NewTestKeyProvider so no
// host keyring is touched.
func NewStore(root string, keys KeyProvider) (*Store, error) {
	if root == "" {
		return nil, ErrUnsafePath
	}
	root = filepath.Clean(root)
	profilesDir := filepath.Join(root, profilesDirName)
	if err := ensurePrivateDir(root); err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(profilesDir); err != nil {
		return nil, err
	}
	if keys == nil {
		keys = newDefaultKeyProvider()
	}
	store := &Store{
		root:        root,
		profilesDir: profilesDir,
		keys:        keys,
		now:         time.Now,
		newID:       randomProfileID,
	}
	// Recovery is deferred until the first Store operation. The CLI constructs
	// Store before it acquires auth.lock; recovering here would allow two
	// processes to replay the same journal concurrently outside that lock.
	return store, nil
}

// NewStoreWithKey is a convenience for tests and embedders that have an
// already generated 32-byte key. It never writes the key to disk.
func NewStoreWithKey(root string, key []byte) (*Store, error) {
	provider, err := NewStaticKeyProvider(key)
	if err != nil {
		return nil, err
	}
	return NewStore(root, provider)
}

func (s *Store) registryPath() string {
	return filepath.Join(s.root, registryFileName)
}

func (s *Store) journalPath() string {
	return filepath.Join(s.root, profileJournalFileName)
}

func (s *Store) profilePath(id string) string {
	return filepath.Join(s.profilesDir, profileFileName(id))
}

func (s *Store) recoverJournalLocked() error {
	record, present, err := s.readJournalLocked()
	if err != nil || !present {
		return err
	}
	if record.Phase == profileJournalCommitted {
		if err := s.removeJournalLocked(); err != nil {
			return fmt.Errorf("remove committed profile journal: %w", err)
		}
		return nil
	}
	if err := s.restoreJournalStateLocked(record); err != nil {
		return fmt.Errorf("restore profile transaction: %w", err)
	}
	if err := s.removeJournalLocked(); err != nil {
		return fmt.Errorf("remove recovered profile journal: %w", err)
	}
	return nil
}

func (s *Store) readJournalLocked() (profileJournal, bool, error) {
	info, err := os.Lstat(s.journalPath())
	if errors.Is(err, os.ErrNotExist) {
		return profileJournal{}, false, nil
	}
	if err != nil {
		return profileJournal{}, false, fmt.Errorf("inspect profile journal: %w", err)
	}
	if !info.Mode().IsRegular() || !ownedByCurrentUser(info) || !privateFilePermissions(s.journalPath(), info) || validateProfilePathOwner(s.journalPath()) != nil {
		return profileJournal{}, false, fmt.Errorf("%w: unsafe journal file", ErrProfileJournal)
	}
	data, err := secureReadFile(s.journalPath(), maxProfileJournalBytes)
	if err != nil {
		return profileJournal{}, false, fmt.Errorf("read profile journal: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record profileJournal
	if err := decoder.Decode(&record); err != nil {
		return profileJournal{}, false, fmt.Errorf("%w: decode journal", ErrProfileJournal)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return profileJournal{}, false, fmt.Errorf("%w: trailing journal data", ErrProfileJournal)
	}
	if err := s.validateJournalRecord(record); err != nil {
		return profileJournal{}, false, err
	}
	return record, true, nil
}

func (s *Store) validateJournalRecord(record profileJournal) error {
	if record.SchemaVersion != profileJournalSchemaVersion ||
		(record.Operation != "save" && record.Operation != "remove") ||
		(record.Phase != profileJournalPrepared && record.Phase != profileJournalCommitted) {
		return fmt.Errorf("%w: unsupported journal metadata", ErrProfileJournal)
	}
	if filepath.Clean(record.RegistryPath) != filepath.Clean(s.registryPath()) {
		return fmt.Errorf("%w: journal paths do not match store", ErrProfileJournal)
	}
	profileBase := filepath.Base(record.ProfilePath)
	profileID := strings.TrimSuffix(profileBase, ".enc")
	if !strings.HasSuffix(profileBase, ".enc") || !validProfileID(profileID) ||
		filepath.Clean(record.ProfilePath) != filepath.Clean(s.profilePath(profileID)) {
		return fmt.Errorf("%w: invalid profile target", ErrProfileJournal)
	}
	if record.RegistryPresent {
		if len(record.OldRegistry) == 0 || int64(len(record.OldRegistry)) > maxRegistryBytes {
			return fmt.Errorf("%w: invalid old registry", ErrProfileJournal)
		}
		if _, err := decodeRegistry(record.OldRegistry); err != nil {
			return fmt.Errorf("%w: invalid old registry", ErrProfileJournal)
		}
	} else if len(record.OldRegistry) != 0 {
		return fmt.Errorf("%w: absent registry has payload", ErrProfileJournal)
	}
	if record.ProfilePresent {
		if !validEncryptedProfileBlob(record.OldProfile) {
			return fmt.Errorf("%w: invalid old profile blob", ErrProfileJournal)
		}
	} else if len(record.OldProfile) != 0 {
		return fmt.Errorf("%w: absent profile has payload", ErrProfileJournal)
	}
	return nil
}

func validEncryptedProfileBlob(blob []byte) bool {
	return int64(len(blob)) >= int64(profileHeaderLen)+chacha20poly1305.Overhead &&
		int64(len(blob)) <= maxProfileFileBytes &&
		bytes.Equal(blob[:len(profileMagic)], profileMagic) &&
		blob[len(profileMagic)] == profileFileVersion
}

func (s *Store) writeJournalLocked(record profileJournal) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode profile journal: %w", err)
	}
	if int64(len(data)) > maxProfileJournalBytes {
		return ErrPayloadTooLarge
	}
	return secureWriteFile(s.journalPath(), data)
}

func (s *Store) removeJournalLocked() error {
	err := secureRemoveFile(s.journalPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *Store) restoreJournalStateLocked(record profileJournal) error {
	if record.ProfilePresent {
		if err := secureWriteFile(record.ProfilePath, record.OldProfile); err != nil {
			return fmt.Errorf("restore encrypted profile: %w", err)
		}
	} else if err := secureRemoveFile(record.ProfilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove interrupted profile: %w", err)
	}
	if record.RegistryPresent {
		if err := secureWriteFile(record.RegistryPath, record.OldRegistry); err != nil {
			return fmt.Errorf("restore profile registry: %w", err)
		}
	} else if err := secureRemoveFile(record.RegistryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove interrupted registry: %w", err)
	}
	return nil
}

func (s *Store) abortProfileMutation(record profileJournal, cause error) error {
	if restoreErr := s.restoreJournalStateLocked(record); restoreErr != nil {
		return errors.Join(cause, fmt.Errorf("profile rollback failed; journal retained: %w", restoreErr))
	}
	if removeErr := s.removeJournalLocked(); removeErr != nil {
		return errors.Join(cause, fmt.Errorf("remove profile rollback journal: %w", removeErr))
	}
	return cause
}

func (s *Store) registrySnapshotLocked() ([]byte, bool, error) {
	data, err := secureReadFile(s.registryPath(), maxRegistryBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if _, err := decodeRegistry(data); err != nil {
		return nil, false, err
	}
	return copyBytes(data), true, nil
}

// Save encrypts and persists the complete SessionBundle under alias. Existing
// aliases retain their immutable profile ID, while a new alias receives a
// cryptographically random ID. Identity matching is done before any write so
// a refreshed account can never overwrite a different account's profile.
func (s *Store) Save(alias string, identity model.Identity, bundle model.SessionBundle) (model.ProfileMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(alias, identity, bundle)
}

// SaveBundle is an explicit synonym for Save for callers that want to make
// telemetry-state rotation visible at the call site.
func (s *Store) SaveBundle(alias string, identity model.Identity, bundle model.SessionBundle) (model.ProfileMetadata, error) {
	return s.Save(alias, identity, bundle)
}

func (s *Store) saveLocked(alias string, identity model.Identity, bundle model.SessionBundle) (model.ProfileMetadata, error) {
	if err := validateAlias(alias); err != nil {
		return model.ProfileMetadata{}, err
	}
	if err := validateBundle(bundle); err != nil {
		return model.ProfileMetadata{}, err
	}
	identity, err := normalizeIdentity(identity)
	if err != nil {
		return model.ProfileMetadata{}, err
	}
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return model.ProfileMetadata{}, err
	}
	oldRegistry, registryPresent, err := s.registrySnapshotLocked()
	if err != nil {
		return model.ProfileMetadata{}, err
	}

	existing, aliasExists := registry.Profiles[alias]
	if aliasExists {
		if existing.AccountID != identity.AccountID || existing.Provider != identity.Provider {
			return model.ProfileMetadata{}, ErrAliasIdentityMismatch
		}
	} else if duplicateAlias, duplicate := findIdentity(registry, identity); duplicate {
		return model.ProfileMetadata{}, fmt.Errorf("%w: %s", ErrDuplicateIdentity, duplicateAlias)
	}

	profileID := existing.ProfileID
	if profileID == "" {
		profileID, err = s.uniqueProfileIDLocked(registry)
		if err != nil {
			return model.ProfileMetadata{}, err
		}
	}
	metadata := model.ProfileMetadata{
		ProfileID:    profileID,
		AccountID:    identity.AccountID,
		Provider:     identity.Provider,
		LastSynced:   s.now().UTC(),
		HasTelemetry: bundle.TelemetryPresent,
		Adapter:      model.DefaultAdapterMetadata(),
	}

	key, err := s.masterKey()
	if err != nil {
		return model.ProfileMetadata{}, err
	}
	blob, err := encryptProfile(profileID, identity, bundle, key)
	clearBytes(key)
	if err != nil {
		return model.ProfileMetadata{}, err
	}
	oldProfile, profilePresent := []byte(nil), false
	if aliasExists {
		oldProfile, err = secureReadFile(s.profilePath(profileID), maxProfileFileBytes)
		if errors.Is(err, os.ErrNotExist) {
			return model.ProfileMetadata{}, fmt.Errorf("%w: profile data missing", ErrCorrupt)
		}
		if err != nil {
			return model.ProfileMetadata{}, err
		}
		profilePresent = true
	}

	if registry.Profiles == nil {
		registry.Profiles = make(map[string]model.ProfileMetadata)
	}
	registry.Profiles = cloneProfiles(registry.Profiles)
	registry.Profiles[alias] = metadata
	newRegistry, err := encodeRegistry(registry)
	if err != nil {
		return model.ProfileMetadata{}, err
	}
	record := profileJournal{
		SchemaVersion:   profileJournalSchemaVersion,
		Operation:       "save",
		Phase:           profileJournalPrepared,
		RegistryPath:    s.registryPath(),
		ProfilePath:     s.profilePath(profileID),
		RegistryPresent: registryPresent,
		OldRegistry:     oldRegistry,
		ProfilePresent:  profilePresent,
		OldProfile:      oldProfile,
	}
	if err := s.writeJournalLocked(record); err != nil {
		return model.ProfileMetadata{}, err
	}
	if err := secureWriteFile(record.ProfilePath, blob); err != nil {
		return model.ProfileMetadata{}, s.abortProfileMutation(record, err)
	}
	if err := secureWriteFile(record.RegistryPath, newRegistry); err != nil {
		return model.ProfileMetadata{}, s.abortProfileMutation(record, err)
	}
	record.Phase = profileJournalCommitted
	if err := s.writeJournalLocked(record); err != nil {
		return model.ProfileMetadata{}, s.abortProfileMutation(record, err)
	}
	if err := s.removeJournalLocked(); err != nil {
		// The committed marker leaves an unambiguous new state for the next
		// Store operation to finish cleaning up.
		return model.ProfileMetadata{}, err
	}
	return metadata, nil
}

func (s *Store) uniqueProfileIDLocked(registry model.Registry) (string, error) {
	for i := 0; i < 32; i++ {
		id, err := s.newID()
		if err != nil {
			return "", err
		}
		if validProfileID(id) && !profileIDInRegistry(registry, id) {
			if _, err := os.Lstat(s.profilePath(id)); errors.Is(err, os.ErrNotExist) {
				return id, nil
			} else if err != nil {
				return "", fmt.Errorf("inspect profile file: %w", err)
			}
		}
	}
	return "", fmt.Errorf("generate unique profile identifier")
}

// Load decrypts a profile by alias and verifies the profile's authenticated
// identity and immutable ID against the registry. Returned byte slices are
// copies and include telemetry-state.json exactly as supplied to Save.
func (s *Store) Load(alias string) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateAlias(alias); err != nil {
		return Profile{}, err
	}
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return Profile{}, err
	}
	metadata, ok := registry.Profiles[alias]
	if !ok {
		return Profile{}, ErrNotFound
	}
	if !validProfileID(metadata.ProfileID) {
		return Profile{}, ErrCorrupt
	}
	blob, err := secureReadFile(s.profilePath(metadata.ProfileID), maxProfileFileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Profile{}, fmt.Errorf("%w: profile data missing", ErrCorrupt)
		}
		return Profile{}, err
	}
	key, err := s.masterKey()
	if err != nil {
		return Profile{}, err
	}
	identity, bundle, decryptErr := decryptProfile(metadata.ProfileID, blob, key)
	clearBytes(key)
	if decryptErr != nil {
		return Profile{}, decryptErr
	}
	if identity.AccountID != metadata.AccountID || identity.Provider != metadata.Provider {
		return Profile{}, ErrCorrupt
	}
	if metadata.HasTelemetry != bundle.TelemetryPresent {
		return Profile{}, ErrCorrupt
	}
	return Profile{Alias: alias, Metadata: metadata, Bundle: model.SessionBundle{
		Credentials:      copyBytes(bundle.Credentials),
		Telemetry:        copyBytes(bundle.Telemetry),
		TelemetryPresent: bundle.TelemetryPresent,
	}}, nil
}

// Get is a short alias for Load.
func (s *Store) Get(alias string) (Profile, error) {
	return s.Load(alias)
}

// LoadByID loads an immutable profile ID after resolving its registry entry.
// It fails when the ID is not registered, preventing callers from treating
// arbitrary files in profiles/ as profiles.
func (s *Store) LoadByID(id string) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validProfileID(id) {
		return Profile{}, ErrNotFound
	}
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return Profile{}, err
	}
	for alias, metadata := range registry.Profiles {
		if metadata.ProfileID == id {
			return s.loadEntryLocked(alias, metadata)
		}
	}
	return Profile{}, ErrNotFound
}

func (s *Store) loadEntryLocked(alias string, metadata model.ProfileMetadata) (Profile, error) {
	if !validProfileID(metadata.ProfileID) {
		return Profile{}, ErrCorrupt
	}
	blob, err := secureReadFile(s.profilePath(metadata.ProfileID), maxProfileFileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Profile{}, fmt.Errorf("%w: profile data missing", ErrCorrupt)
		}
		return Profile{}, err
	}
	key, err := s.masterKey()
	if err != nil {
		return Profile{}, err
	}
	identity, bundle, decryptErr := decryptProfile(metadata.ProfileID, blob, key)
	clearBytes(key)
	if decryptErr != nil {
		return Profile{}, decryptErr
	}
	if identity.AccountID != metadata.AccountID || identity.Provider != metadata.Provider || metadata.HasTelemetry != bundle.TelemetryPresent {
		return Profile{}, ErrCorrupt
	}
	return Profile{Alias: alias, Metadata: metadata, Bundle: model.SessionBundle{
		Credentials:      copyBytes(bundle.Credentials),
		Telemetry:        copyBytes(bundle.Telemetry),
		TelemetryPresent: bundle.TelemetryPresent,
	}}, nil
}

// List returns every registered profile in deterministic alias order. It
// validates each registry pointer and scans the profile directory, returning an
// orphan error rather than silently dropping or deleting unregistered data.
func (s *Store) List() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return nil, err
	}
	aliases := make([]string, 0, len(registry.Profiles))
	for alias := range registry.Profiles {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	entries := make([]Entry, 0, len(aliases))
	knownIDs := make(map[string]struct{}, len(aliases))
	for _, alias := range aliases {
		metadata := registry.Profiles[alias]
		if !validProfileID(metadata.ProfileID) {
			return entries, ErrCorrupt
		}
		knownIDs[metadata.ProfileID] = struct{}{}
		info, statErr := os.Lstat(s.profilePath(metadata.ProfileID))
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				return entries, fmt.Errorf("%w: profile data missing", ErrCorrupt)
			}
			return entries, statErr
		}
		if err := validateOwnerAndType(info, false); err != nil || !privateFilePermissions(s.profilePath(metadata.ProfileID), info) {
			return entries, ErrUnsafePath
		}
		if err := validateProfilePathOwner(s.profilePath(metadata.ProfileID)); err != nil {
			return entries, err
		}
		entries = append(entries, Entry{Alias: alias, Metadata: metadata})
	}
	if err := s.checkForOrphansLocked(knownIDs); err != nil {
		return entries, err
	}
	return entries, nil
}

// ListMetadata returns only metadata for callers that do not need aliases in
// the result type. The order is the same deterministic alias order as List.
func (s *Store) ListMetadata() ([]model.ProfileMetadata, error) {
	entries, err := s.List()
	metadata := make([]model.ProfileMetadata, 0, len(entries))
	for _, entry := range entries {
		metadata = append(metadata, entry.Metadata)
	}
	return metadata, err
}

func (s *Store) checkForOrphansLocked(knownIDs map[string]struct{}) error {
	entries, err := readDirEntries(s.profilesDir)
	if err != nil {
		return fmt.Errorf("scan profile directory: %w", err)
	}
	for _, entry := range entries {
		info, statErr := entry.Info()
		if statErr != nil {
			return fmt.Errorf("inspect profile directory entry: %w", statErr)
		}
		if err := validateOwnerAndType(info, false); err != nil {
			return err
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".enc") {
			return ErrOrphanedProfile
		}
		id := strings.TrimSuffix(name, ".enc")
		if !validProfileID(id) {
			return ErrOrphanedProfile
		}
		if _, ok := knownIDs[id]; !ok {
			return ErrOrphanedProfile
		}
	}
	return nil
}

// Remove removes exactly one alias and its corresponding encrypted profile.
// Missing aliases, missing profile files, symlinks, corrupt permissions, and
// registry write failures are returned to the caller; no broad or silent
// deletion occurs.
func (s *Store) Remove(alias string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateAlias(alias); err != nil {
		return err
	}
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return err
	}
	oldRegistry, registryPresent, err := s.registrySnapshotLocked()
	if err != nil {
		return err
	}
	metadata, ok := registry.Profiles[alias]
	if !ok {
		return ErrNotFound
	}
	if !validProfileID(metadata.ProfileID) {
		return ErrCorrupt
	}
	profilePath := s.profilePath(metadata.ProfileID)
	oldProfile, err := secureReadFile(profilePath, maxProfileFileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: profile data missing", ErrCorrupt)
		}
		return err
	}
	registry.Profiles = cloneProfiles(registry.Profiles)
	delete(registry.Profiles, alias)
	if registry.ActiveProfile == alias {
		registry.ActiveProfile = ""
	}
	if registry.PreviousProfile == alias {
		registry.PreviousProfile = ""
	}
	newRegistry, err := encodeRegistry(registry)
	if err != nil {
		return err
	}
	record := profileJournal{
		SchemaVersion:   profileJournalSchemaVersion,
		Operation:       "remove",
		Phase:           profileJournalPrepared,
		RegistryPath:    s.registryPath(),
		ProfilePath:     profilePath,
		RegistryPresent: registryPresent,
		OldRegistry:     oldRegistry,
		ProfilePresent:  true,
		OldProfile:      oldProfile,
	}
	if err := s.writeJournalLocked(record); err != nil {
		return err
	}
	if err := secureWriteFile(record.RegistryPath, newRegistry); err != nil {
		return s.abortProfileMutation(record, err)
	}
	if err := secureRemoveFile(record.ProfilePath); err != nil {
		return s.abortProfileMutation(record, err)
	}
	record.Phase = profileJournalCommitted
	if err := s.writeJournalLocked(record); err != nil {
		return s.abortProfileMutation(record, err)
	}
	if err := s.removeJournalLocked(); err != nil {
		return err
	}
	return nil
}

// Registry returns a copy of the registry, including active/previous alias
// pointers. It never returns encrypted payloads.
func (s *Store) Registry() (model.Registry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return model.Registry{}, err
	}
	return cloneRegistry(registry), nil
}

// SetActive records the current alias and moves the former active alias to
// previous. Passing an empty alias clears the current pointer without deleting
// any profile.
func (s *Store) SetActive(alias string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return err
	}
	if alias != "" {
		if err := validateAlias(alias); err != nil {
			return err
		}
		if _, ok := registry.Profiles[alias]; !ok {
			return ErrNotFound
		}
	}
	if alias != registry.ActiveProfile {
		registry.PreviousProfile = registry.ActiveProfile
	}
	registry.ActiveProfile = alias
	return s.writeRegistryLocked(registry)
}

// SetActivePair stores both pointers exactly. It is useful to restore a
// transaction's previous/current aliases after a crash recovery.
func (s *Store) SetActivePair(active, previous string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := s.loadRegistryLocked()
	if err != nil {
		return err
	}
	for _, alias := range []string{active, previous} {
		if alias == "" {
			continue
		}
		if err := validateAlias(alias); err != nil {
			return err
		}
		if _, ok := registry.Profiles[alias]; !ok {
			return ErrNotFound
		}
	}
	registry.ActiveProfile = active
	registry.PreviousProfile = previous
	return s.writeRegistryLocked(registry)
}

func (s *Store) loadRegistryLocked() (model.Registry, error) {
	if err := ensurePrivateDir(s.root); err != nil {
		return model.Registry{}, err
	}
	if err := ensurePrivateDir(s.profilesDir); err != nil {
		return model.Registry{}, err
	}
	if err := s.recoverJournalLocked(); err != nil {
		return model.Registry{}, err
	}
	b, err := secureReadFile(s.registryPath(), maxRegistryBytes)
	if errors.Is(err, os.ErrNotExist) {
		return model.Registry{SchemaVersion: model.SchemaVersion, Profiles: make(map[string]model.ProfileMetadata)}, nil
	}
	if err != nil {
		return model.Registry{}, err
	}
	return decodeRegistry(b)
}

func decodeRegistry(data []byte) (model.Registry, error) {
	if err := rejectDuplicateRegistryKeys(data); err != nil {
		return model.Registry{}, ErrCorrupt
	}
	var registry model.Registry
	if err := json.Unmarshal(data, &registry); err != nil {
		return model.Registry{}, ErrCorrupt
	}
	if registry.SchemaVersion != model.SchemaVersion {
		return model.Registry{}, ErrUnsupportedVersion
	}
	if registry.Profiles == nil {
		registry.Profiles = make(map[string]model.ProfileMetadata)
	}
	for alias, metadata := range registry.Profiles {
		normalized, err := model.NormalizeAdapterMetadata(metadata.Adapter)
		if err != nil {
			return model.Registry{}, ErrUnsupportedVersion
		}
		metadata.Adapter = normalized
		registry.Profiles[alias] = metadata
	}
	if err := validateRegistry(registry); err != nil {
		return model.Registry{}, err
	}
	return registry, nil
}

func rejectDuplicateRegistryKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var scan func() error
	scan = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrCorrupt
				}
				if _, exists := seen[key]; exists {
					return ErrCorrupt
				}
				seen[key] = struct{}{}
				if err := scan(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := scan(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrCorrupt
		}
	}
	if err := scan(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrCorrupt
	}
	return nil
}

func (s *Store) writeRegistryLocked(registry model.Registry) error {
	b, err := encodeRegistry(registry)
	if err != nil {
		return err
	}
	return secureWriteFile(s.registryPath(), b)
}

func encodeRegistry(registry model.Registry) ([]byte, error) {
	if registry.SchemaVersion == 0 {
		registry.SchemaVersion = model.SchemaVersion
	}
	if err := validateRegistry(registry); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode profile registry: %w", err)
	}
	b = append(b, '\n')
	if int64(len(b)) > maxRegistryBytes {
		return nil, ErrCorrupt
	}
	return b, nil
}

func (s *Store) masterKey() ([]byte, error) {
	key, err := s.keys.MasterKey(context.Background())
	if err != nil {
		if errors.Is(err, ErrInvalidKey) {
			return nil, ErrInvalidKey
		}
		return nil, ErrKeyUnavailable
	}
	if len(key) != 32 {
		clearBytes(key)
		return nil, ErrInvalidKey
	}
	copyOfKey := copyBytes(key)
	clearBytes(key)
	return copyOfKey, nil
}

// CheckKey verifies that an existing master key is available without
// initializing a new Secret Service item.
func (s *Store) CheckKey(ctx context.Context) error {
	if s == nil || s.keys == nil {
		return ErrKeyUnavailable
	}
	var (
		key []byte
		err error
	)
	if provider, ok := s.keys.(ExistingKeyProvider); ok {
		key, err = provider.ExistingKey(ctx)
	} else {
		key, err = s.keys.MasterKey(ctx)
	}
	if err != nil {
		return ErrKeyUnavailable
	}
	defer clearBytes(key)
	if len(key) != masterKeySize {
		return ErrInvalidKey
	}
	return nil
}

func validateAlias(alias string) error {
	if alias == "" || len(alias) > 64 || alias != strings.TrimSpace(alias) || alias == "." || alias == ".." {
		return ErrInvalidAlias
	}
	for i, r := range alias {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || (i > 0 && (r == '-' || r == '_' || r == '.')) {
			continue
		}
		return ErrInvalidAlias
	}
	return nil
}

func normalizeIdentity(identity model.Identity) (model.Identity, error) {
	identity.AccountID = strings.TrimSpace(identity.AccountID)
	identity.Provider = strings.TrimSpace(identity.Provider)
	if identity.AccountID == "" || identity.Provider == "" ||
		len(identity.AccountID) > 512 || len(identity.Provider) > 128 ||
		!safeIdentityText(identity.AccountID) || !safeIdentityText(identity.Provider) {
		return model.Identity{}, ErrInvalidIdentity
	}
	return identity, nil
}

func safeIdentityText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validateRegistry(registry model.Registry) error {
	if registry.SchemaVersion != model.SchemaVersion {
		return ErrUnsupportedVersion
	}
	seenIDs := make(map[string]struct{}, len(registry.Profiles))
	seenIdentities := make(map[string]struct{}, len(registry.Profiles))
	for alias, metadata := range registry.Profiles {
		if err := validateAlias(alias); err != nil || !validProfileID(metadata.ProfileID) {
			return ErrCorrupt
		}
		if _, err := normalizeIdentity(model.Identity{AccountID: metadata.AccountID, Provider: metadata.Provider}); err != nil {
			return ErrCorrupt
		}
		if _, exists := seenIDs[metadata.ProfileID]; exists {
			return ErrCorrupt
		}
		seenIDs[metadata.ProfileID] = struct{}{}
		identityKey := metadata.Provider + "\x00" + metadata.AccountID
		if _, exists := seenIdentities[identityKey]; exists {
			return ErrCorrupt
		}
		seenIdentities[identityKey] = struct{}{}
	}
	for _, pointer := range []string{registry.ActiveProfile, registry.PreviousProfile} {
		if pointer == "" {
			continue
		}
		if err := validateAlias(pointer); err != nil {
			return ErrCorrupt
		}
		if _, ok := registry.Profiles[pointer]; !ok {
			return ErrCorrupt
		}
	}
	return nil
}

func findIdentity(registry model.Registry, identity model.Identity) (string, bool) {
	for alias, metadata := range registry.Profiles {
		if metadata.AccountID == identity.AccountID && metadata.Provider == identity.Provider {
			return alias, true
		}
	}
	return "", false
}

func profileIDInRegistry(registry model.Registry, id string) bool {
	for _, metadata := range registry.Profiles {
		if metadata.ProfileID == id {
			return true
		}
	}
	return false
}

func cloneProfiles(profiles map[string]model.ProfileMetadata) map[string]model.ProfileMetadata {
	copyMap := make(map[string]model.ProfileMetadata, len(profiles))
	for alias, metadata := range profiles {
		copyMap[alias] = metadata
	}
	return copyMap
}

func cloneRegistry(registry model.Registry) model.Registry {
	registry.Profiles = cloneProfiles(registry.Profiles)
	return registry
}
