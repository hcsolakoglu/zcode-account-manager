package profile

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hcsolakoglu/zcode-account-manager/internal/model"
)

const (
	profileFileVersion = byte(1)
	profileHeaderLen   = 8 + 1 + chacha20poly1305.NonceSizeX
	profileSchema      = 1
)

var profileMagic = []byte{'Z', 'C', 'O', 'D', 'E', 'P', 'R', 'F'}

type encryptedProfile struct {
	SchemaVersion int                 `json:"schema_version"`
	ProfileID     string              `json:"profile_id"`
	Identity      model.Identity      `json:"identity"`
	Session       model.SessionBundle `json:"session"`
}

func randomProfileID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate profile identifier: %w", err)
	}
	// Hex is intentionally used instead of a UUID dependency. It is path-safe,
	// opaque, and generated from the OS CSPRNG.
	return hex.EncodeToString(b), nil
}

func encryptProfile(id string, identity model.Identity, bundle model.SessionBundle, key []byte) ([]byte, error) {
	if err := validateBundle(bundle); err != nil {
		return nil, err
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKey
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalidKey
	}
	payload, err := json.Marshal(encryptedProfile{
		SchemaVersion: profileSchema,
		ProfileID:     id,
		Identity:      identity,
		Session:       bundle,
	})
	if err != nil {
		return nil, fmt.Errorf("encode profile: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate profile nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, payload, profileAAD(id))
	result := make([]byte, 0, profileHeaderLen+len(ciphertext))
	result = append(result, profileMagic...)
	result = append(result, profileFileVersion)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	if int64(len(result)) > maxProfileFileBytes {
		return nil, ErrInvalidBundle
	}
	return result, nil
}

func decryptProfile(id string, blob, key []byte) (model.Identity, model.SessionBundle, error) {
	if len(key) != chacha20poly1305.KeySize {
		return model.Identity{}, model.SessionBundle{}, ErrInvalidKey
	}
	if len(blob) < profileHeaderLen+chacha20poly1305.Overhead {
		return model.Identity{}, model.SessionBundle{}, ErrCorrupt
	}
	if int64(len(blob)) > maxProfileFileBytes {
		return model.Identity{}, model.SessionBundle{}, ErrCorrupt
	}
	if !bytes.Equal(blob[:len(profileMagic)], profileMagic) || blob[len(profileMagic)] != profileFileVersion {
		return model.Identity{}, model.SessionBundle{}, ErrCorrupt
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return model.Identity{}, model.SessionBundle{}, ErrInvalidKey
	}
	nonceStart := len(profileMagic) + 1
	nonceEnd := nonceStart + chacha20poly1305.NonceSizeX
	plaintext, err := aead.Open(nil, blob[nonceStart:nonceEnd], blob[nonceEnd:], profileAAD(id))
	if err != nil {
		return model.Identity{}, model.SessionBundle{}, ErrAuthentication
	}
	var profile encryptedProfile
	if err := json.Unmarshal(plaintext, &profile); err != nil {
		return model.Identity{}, model.SessionBundle{}, ErrCorrupt
	}
	if profile.SchemaVersion != profileSchema || profile.ProfileID != id {
		return model.Identity{}, model.SessionBundle{}, ErrCorrupt
	}
	if profile.Identity.AccountID == "" || profile.Identity.Provider == "" {
		return model.Identity{}, model.SessionBundle{}, ErrCorrupt
	}
	if err := validateBundle(profile.Session); err != nil {
		return model.Identity{}, model.SessionBundle{}, ErrCorrupt
	}
	return profile.Identity, profile.Session, nil
}

func validateBundle(bundle model.SessionBundle) error {
	if len(bundle.Credentials) == 0 || len(bundle.Credentials) > maxCredentialsBytes {
		return ErrInvalidBundle
	}
	if len(bundle.Telemetry) > maxTelemetryBytes {
		return ErrInvalidBundle
	}
	if !bundle.TelemetryPresent && len(bundle.Telemetry) != 0 {
		return ErrInvalidBundle
	}
	return nil
}

func profileAAD(id string) []byte {
	const prefix = "zcode-auth/profile/v1/"
	result := make([]byte, 0, len(prefix)+len(id))
	result = append(result, prefix...)
	result = append(result, id...)
	return result
}
