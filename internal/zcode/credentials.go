package zcode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hcsolakoglu/zcode-account-manager/internal/model"
)

const maxStateBytes = 32 << 20

// State is an opaque pair of account-scoped documents.  Credentials and
// telemetry are returned exactly as read; no JSON re-marshalling occurs.
type State = model.SessionBundle

// ReadState reads credentials and the optional telemetry companion.  A missing
// telemetry-state.json is normal for older ZCode installations and results in
// a nil Telemetry field.  Credentials must be present and a valid JSON object.
func ReadState(paths Paths) (model.SessionBundle, error) {
	credentials, err := ReadCredentials(paths.CredentialsPath)
	if err != nil {
		return model.SessionBundle{}, err
	}
	telemetry, err := readOptionalDocument(paths.TelemetryPath, ValidateTelemetry)
	if err != nil {
		return model.SessionBundle{}, err
	}
	return model.SessionBundle{Credentials: credentials, Telemetry: telemetry, TelemetryPresent: telemetry != nil}, nil
}

// ReadCredentials reads one credentials document without normalizing it.
func ReadCredentials(path string) ([]byte, error) {
	data, err := readDocument(path, ValidateCredentials)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ReadTelemetry reads one telemetry document without normalizing it.  Missing
// telemetry is returned as os.ErrNotExist, allowing callers to distinguish it
// from an unsafe or malformed file.
func ReadTelemetry(path string) ([]byte, error) {
	return readDocument(path, ValidateTelemetry)
}

// ValidateCredentials performs only structural validation.  Credential values
// remain opaque and unknown fields are deliberately accepted.
func ValidateCredentials(data []byte) error {
	if _, err := decodeObject(data); err != nil {
		return fmt.Errorf("%w: credentials", ErrInvalidState)
	}
	return nil
}

// ValidateTelemetry performs only structural validation.  ZCode currently
// writes an object and the adapter preserves every object member verbatim.
func ValidateTelemetry(data []byte) error {
	if _, err := decodeObject(data); err != nil {
		return fmt.Errorf("%w: telemetry", ErrInvalidState)
	}
	return nil
}

// WriteState writes both documents using same-directory temporary files,
// fsync, and atomic rename.  Credential bytes and telemetry bytes are not
// re-marshaled.  TelemetryPresent is authoritative: false removes the
// companion file after validating it is safe, while true writes the supplied
// opaque bytes.
func WriteState(paths Paths, state model.SessionBundle) error {
	if err := ValidateCredentials(state.Credentials); err != nil {
		return err
	}
	if state.TelemetryPresent {
		if state.Telemetry == nil {
			return fmt.Errorf("telemetry is marked present but has no bytes")
		}
		if err := ValidateTelemetry(state.Telemetry); err != nil {
			return err
		}
	}
	if err := writeDocument(paths.CredentialsPath, state.Credentials); err != nil {
		return err
	}
	if state.TelemetryPresent {
		if err := writeDocument(paths.TelemetryPath, state.Telemetry); err != nil {
			return err
		}
	} else if err := removeDocument(paths.TelemetryPath); err != nil {
		return err
	}
	return nil
}

// WriteCredentials atomically replaces credentials.json with opaque bytes.
func WriteCredentials(path string, data []byte) error {
	if err := ValidateCredentials(data); err != nil {
		return err
	}
	return writeDocument(path, data)
}

// WriteTelemetry atomically replaces telemetry-state.json with opaque bytes.
func WriteTelemetry(path string, data []byte) error {
	if err := ValidateTelemetry(data); err != nil {
		return err
	}
	return writeDocument(path, data)
}

// ClearState keeps the two files present but removes account-scoped contents.
// Empty JSON objects are valid ZCode stores and avoid a missing-file race with
// the desktop client.  Stored profile blobs are unaffected by this operation.
func ClearState(paths Paths) error {
	if err := writeDocument(paths.CredentialsPath, []byte("{}")); err != nil {
		return err
	}
	return writeDocument(paths.TelemetryPath, []byte("{}"))
}

// ClearTelemetry clears only the account-scoped telemetry companion.
func ClearTelemetry(path string) error {
	return writeDocument(path, []byte("{}"))
}

// RemoveStateFiles unlinks the two state files after validating that each is a
// user-owned regular file.  It is provided for an explicit logout policy; the
// safer default is ClearState, which retains empty valid stores.
func RemoveStateFiles(paths Paths) error {
	for _, path := range []string{paths.CredentialsPath, paths.TelemetryPath} {
		if err := removeDocument(path); err != nil {
			return err
		}
	}
	return nil
}

func removeDocument(path string) error {
	if err := ValidateSensitivePath(path, true); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove zcode state: %w", err)
	}
	return nil
}

func readDocument(path string, validate func([]byte) error) ([]byte, error) {
	if err := ValidateSensitiveDirectory(filepath.Dir(filepath.Clean(path)), false); err != nil {
		return nil, err
	}
	if err := ValidateSensitivePath(path, false); err != nil {
		return nil, err
	}

	// O_NOFOLLOW closes the lstat/open gap for the final component.  Parent
	// components were checked above and are never traversed with elevated
	// privileges by this process.
	fd, err := openStateRead(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	info, err := fd.Stat()
	if err != nil {
		return nil, err
	}
	if err := validateOwner(info); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: state file", ErrUnsafeStatePath)
	}
	data, err := io.ReadAll(io.LimitReader(fd, maxStateBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read zcode state: %w", err)
	}
	if len(data) > maxStateBytes {
		return nil, fmt.Errorf("zcode state exceeds size limit")
	}
	if err := validate(data); err != nil {
		return nil, err
	}
	return data, nil
}

func readOptionalDocument(path string, validate func([]byte) error) ([]byte, error) {
	data, err := readDocument(path, validate)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func writeDocument(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("%w: empty path", ErrUnsafeStatePath)
	}
	dir := filepath.Dir(filepath.Clean(path))
	if err := ValidateSensitiveDirectory(dir, true); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create zcode state directory: %w", err)
	}
	if err := ValidateSensitiveDirectory(dir, false); err != nil {
		return err
	}
	if err := hardenStateDirectory(dir); err != nil {
		return fmt.Errorf("secure zcode state directory ACL: %w", err)
	}
	if err := ValidateSensitivePath(path, true); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".zcode-auth-state-*")
	if err != nil {
		return fmt.Errorf("create zcode state temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure zcode state temporary file: %w", err)
	}
	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write zcode state temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync zcode state temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close zcode state temporary file: %w", err)
	}
	if err := hardenStateFile(tmpName); err != nil {
		return fmt.Errorf("secure zcode state temporary file ACL: %w", err)
	}
	if err := replaceStateDocument(tmpName, path); err != nil {
		return fmt.Errorf("replace zcode state: %w", err)
	}
	if err := syncStateDirectory(dir); err != nil {
		return fmt.Errorf("sync zcode state directory: %w", err)
	}
	return nil
}

// IdentityFromCredentials extracts only the stable account identity.  For the
// installed ZCode schema this means decrypting oauth:active_provider and the
// matching oauth:<provider>:user_info value in memory.  A small set of
// explicit field aliases is also accepted for migration fixtures and future
// schema variants.  No token value is ever returned or formatted in errors.
func IdentityFromCredentials(data []byte) (model.Identity, error) {
	return NewCredentialCipher().IdentityFromCredentials(data)
}

// IdentityFromCredentials applies a caller-selected cipher, primarily useful
// for tests that use a deterministic ZCODE_CREDENTIAL_SECRET.
func (c CredentialCipher) IdentityFromCredentials(data []byte) (model.Identity, error) {
	root, err := decodeObject(data)
	if err != nil {
		return model.Identity{}, fmt.Errorf("%w: credentials", ErrInvalidState)
	}
	if identity, ok, err := identityFromZCodeStore(root, c); err != nil {
		return model.Identity{}, err
	} else if ok {
		return identity, nil
	}

	var generic any
	if err := decodeJSON(data, &generic); err != nil {
		return model.Identity{}, fmt.Errorf("%w: credentials", ErrInvalidState)
	}
	identity, err := identityFromGeneric(generic)
	if err != nil {
		return model.Identity{}, err
	}
	if identity.AccountID == "" {
		return model.Identity{}, ErrIdentityNotFound
	}
	return identity, nil
}

// Authenticated reports whether the document contains a stable account
// identity and an authenticated credential marker/token.  It returns false
// for ordinary incomplete login state; malformed encrypted known values are
// returned as errors so a watcher cannot silently accept corrupt state.
func Authenticated(data []byte) (bool, error) {
	return NewCredentialCipher().Authenticated(data)
}

// IsAuthenticated is the no-error convenience form for callers that only
// need a predicate.
func IsAuthenticated(data []byte) bool {
	ok, err := Authenticated(data)
	return err == nil && ok
}

// Authenticated applies a caller-selected cipher.
func (c CredentialCipher) Authenticated(data []byte) (bool, error) {
	root, err := decodeObject(data)
	if err != nil {
		return false, fmt.Errorf("%w: credentials", ErrInvalidState)
	}
	identity, err := c.IdentityFromCredentials(data)
	if err != nil {
		return false, err
	}
	if identity.AccountID == "" {
		return false, ErrNotAuthenticated
	}

	storeAuthenticated, err := isAuthenticatedZCodeStore(root, c)
	if err != nil {
		return false, err
	}
	if storeAuthenticated {
		return true, nil
	}
	var generic any
	if err := decodeJSON(data, &generic); err != nil {
		return false, fmt.Errorf("%w: credentials", ErrInvalidState)
	}
	genericAuthenticated, err := hasGenericAuthMarker(generic, c)
	if err != nil {
		return false, err
	}
	if genericAuthenticated {
		return true, nil
	}
	return false, ErrNotAuthenticated
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := decodeJSON(data, &object); err != nil || object == nil {
		return nil, ErrInvalidState
	}
	return object, nil
}

func decodeJSON(data []byte, destination any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
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
					return errors.New("invalid JSON object key")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate JSON object key")
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
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := scan(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON")
		}
		return err
	}
	return nil
}

func stringRawField(raw json.RawMessage) (string, bool) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

func identityFromZCodeStore(root map[string]json.RawMessage, cipher CredentialCipher) (model.Identity, bool, error) {
	activeRaw, exists := root["oauth:active_provider"]
	if !exists {
		return model.Identity{}, false, nil
	}
	active, ok := stringRawField(activeRaw)
	if !ok {
		return model.Identity{}, true, ErrIdentityNotFound
	}
	provider, err := cipher.DecryptCredentialValue(active)
	if err != nil {
		return model.Identity{}, true, err
	}
	provider, ok = validateIdentityString(provider)
	if !ok {
		return model.Identity{}, true, ErrIdentityNotFound
	}

	userInfoKey := "oauth:" + provider + ":user_info"
	userInfoRaw, exists := root[userInfoKey]
	if !exists {
		// A provider may contain an unexpected separator.  Only fall back to a
		// uniquely matching key; this avoids guessing across accounts.
		var candidates []string
		prefix := "oauth:"
		suffix := ":user_info"
		for key := range root {
			if strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix) {
				candidate := strings.TrimSuffix(strings.TrimPrefix(key, prefix), suffix)
				if candidate == provider {
					candidates = append(candidates, key)
				}
			}
		}
		if len(candidates) == 1 {
			userInfoRaw = root[candidates[0]]
			exists = true
		}
	}
	if !exists {
		return model.Identity{}, true, ErrIdentityNotFound
	}
	userInfo, ok := stringRawField(userInfoRaw)
	if !ok {
		return model.Identity{}, true, ErrIdentityNotFound
	}
	userInfo, err = cipher.DecryptCredentialValue(userInfo)
	if err != nil {
		return model.Identity{}, true, err
	}
	var info map[string]any
	if err := decodeJSON([]byte(userInfo), &info); err != nil || info == nil {
		return model.Identity{}, true, ErrIdentityNotFound
	}
	accountID, err := strictIdentityFromObject(info)
	if err != nil {
		return model.Identity{}, true, err
	}
	if accountID == "" {
		return model.Identity{}, true, ErrIdentityNotFound
	}
	return model.Identity{AccountID: accountID, Provider: provider}, true, nil
}

func identityFromGeneric(root any) (model.Identity, error) {
	identity := model.Identity{}
	identity.Provider = findStringByKeys(root, map[string]struct{}{
		"provider": {}, "provider_id": {}, "providerId": {}, "active_provider": {},
	})
	accountID, err := findStableID(root)
	if err != nil {
		return model.Identity{}, err
	}
	identity.AccountID = accountID
	return identity, nil
}

func findStableID(root any) (string, error) {
	// Explicit account/user identifiers have priority regardless of nesting.
	var candidates []string
	for _, keys := range [][]string{
		{"account_id", "accountId", "accountID"},
		{"user_id", "userId", "userID"},
		{"uid"},
		{"subject", "sub"},
	} {
		candidates = append(candidates, findAllStringsByKeys(root, makeKeySet(keys...))...)
	}
	candidates = append(candidates, findAllContextualIDs(root, nil)...)
	candidates = uniqueStrings(candidates)
	if len(candidates) > 1 {
		return "", ErrIdentityConflict
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	return "", nil
}

func findAllContextualIDs(value any, path []string) []string {
	result := []string{}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			lower := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
			if lower == "id" && hasIdentityContext(path) {
				if candidate, ok := scalarString(child); ok && candidate != "" {
					result = append(result, candidate)
				}
			}
			result = append(result, findAllContextualIDs(child, append(path, lower))...)
		}
	case []any:
		for _, child := range typed {
			result = append(result, findAllContextualIDs(child, path)...)
		}
	}
	return result
}

func hasIdentityContext(path []string) bool {
	for _, element := range path {
		switch element {
		case "account", "accounts", "user", "users", "profile", "profiles", "identity", "member", "members", "owner":
			return true
		}
	}
	return false
}

func findStringByKeys(value any, keys map[string]struct{}) string {
	var result string
	var visit func(any)
	visit = func(current any) {
		if result != "" {
			return
		}
		switch typed := current.(type) {
		case map[string]any:
			ordered := make([]string, 0, len(typed))
			for key := range typed {
				ordered = append(ordered, key)
			}
			sort.Strings(ordered)
			for _, key := range ordered {
				if _, wanted := keys[key]; wanted {
					if candidate, ok := scalarString(typed[key]); ok && candidate != "" {
						result = candidate
						return
					}
				}
			}
			for _, key := range ordered {
				visit(typed[key])
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
	return result
}

func makeKeySet(keys ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		result[key] = struct{}{}
	}
	return result
}

func scalarString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return validateIdentityString(typed)
	case json.Number:
		return validateIdentityString(typed.String())
	default:
		return "", false
	}
}

func strictIdentityFromObject(object map[string]any) (string, error) {
	id, _ := scalarString(object["id"])
	userID, _ := scalarString(object["user_id"])
	if userID == "" {
		userID, _ = scalarString(object["userId"])
	}
	if id != "" && userID != "" && id != userID {
		return "", ErrIdentityConflict
	}
	if id != "" {
		return id, nil
	}
	return userID, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value, ok := validateIdentityString(value)
		if !ok {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func findAllStringsByKeys(value any, keys map[string]struct{}) []string {
	result := []string{}
	var visit func(any)
	visit = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, wanted := keys[key]; wanted {
					if candidate, ok := scalarString(child); ok && candidate != "" {
						result = append(result, candidate)
					}
				}
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
	return result
}

func isAuthenticatedZCodeStore(root map[string]json.RawMessage, cipher CredentialCipher) (bool, error) {
	activeRaw, ok := root["oauth:active_provider"]
	if !ok {
		return false, nil
	}
	active, ok := stringRawField(activeRaw)
	if !ok {
		return false, nil
	}
	provider, err := cipher.DecryptCredentialValue(active)
	if err != nil {
		return false, err
	}
	provider, ok = validateIdentityString(provider)
	if !ok {
		return false, nil
	}
	for _, suffix := range []string{"access_token", "refresh_token", "id_token", "token"} {
		key := "oauth:" + provider + ":" + suffix
		if raw, exists := root[key]; exists {
			value, ok := stringRawField(raw)
			if !ok {
				continue
			}
			value, err = cipher.DecryptCredentialValue(value)
			if err != nil {
				return false, err
			}
			if strings.TrimSpace(value) != "" {
				return true, nil
			}
		}
	}
	return false, nil
}

func hasGenericAuthMarker(value any, cipher CredentialCipher) (bool, error) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
			switch normalized {
			case "access_token", "accesstoken", "refresh_token", "refreshtoken", "id_token", "idtoken", "token":
				if candidate, ok := scalarString(child); ok && candidate != "" {
					candidate, err := cipher.DecryptCredentialValue(candidate)
					if err != nil {
						return false, err
					}
					if strings.TrimSpace(candidate) != "" {
						return true, nil
					}
				}
			case "authenticated", "is_authenticated", "logged_in", "loggedin":
				if authenticated, ok := child.(bool); ok && authenticated {
					return true, nil
				}
			}
			if authenticated, err := hasGenericAuthMarker(child, cipher); err != nil {
				return false, err
			} else if authenticated {
				return true, nil
			}
		}
	case []any:
		for _, child := range typed {
			if authenticated, err := hasGenericAuthMarker(child, cipher); err != nil {
				return false, err
			} else if authenticated {
				return true, nil
			}
		}
	}
	return false, nil
}
