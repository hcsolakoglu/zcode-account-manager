package zcode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

const (
	credentialPrefix        = "enc:v1:"
	credentialSecret        = "ZCODE_CREDENTIAL_SECRET"
	credentialCipher        = "aes-256-gcm"
	credentialNonce         = 12
	credentialTag           = 16
	maxCredentialValueBytes = 8 << 20
)

// CredentialCipher implements the format used by ZCode's credential service.
// The adapter never needs to decrypt or re-encrypt a whole credentials.json
// document: opaque document bytes are retained exactly.  This type is only
// used for the two values needed for identity/authentication checks.
type CredentialCipher struct {
	secret string
}

// NewCredentialCipher creates a cipher using ZCODE_CREDENTIAL_SECRET when set,
// or ZCode's documented per-user fallback secret otherwise.
func NewCredentialCipher() CredentialCipher {
	return CredentialCipher{secret: credentialSecretValue(os.Getenv)}
}

// NewCredentialCipherWithSecret is intended for tests and controlled imports.
// Production callers should normally use NewCredentialCipher so key derivation
// remains compatible with the installed ZCode client.
func NewCredentialCipherWithSecret(secret string) CredentialCipher {
	return CredentialCipher{secret: secret}
}

func credentialSecretValue(getenv func(string) string) string {
	if secret := getenv(credentialSecret); secret != "" {
		return secret
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	return fmt.Sprintf("zcode-credential-fallback:%s:%s:%s", runtime.GOOS, home, CurrentUsername())
}

// DeriveCredentialKey returns SHA-256(secret), matching ZCode's AES-256-GCM
// key derivation.  It is provided for compatibility tests; callers should not
// persist or print the returned key.
func DeriveCredentialKey(secret string) []byte {
	digest := sha256.Sum256([]byte(secret))
	return digest[:]
}

// EncryptCredentialValue serializes a value in ZCode's enc:v1 format.  It is
// useful to adapters that need to create a fresh credential entry.  Existing
// credentials should still be copied opaquely whenever possible.
func (c CredentialCipher) EncryptCredentialValue(plaintext string) (string, error) {
	block, err := aes.NewCipher(DeriveCredentialKey(c.secret))
	if err != nil {
		return "", ErrCredentialDecrypt
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, credentialNonce)
	if err != nil {
		return "", ErrCredentialDecrypt
	}
	nonce := make([]byte, credentialNonce)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate credential nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	if len(sealed) < credentialTag {
		return "", ErrCredentialDecrypt
	}
	ciphertext := sealed[:len(sealed)-credentialTag]
	tag := sealed[len(sealed)-credentialTag:]
	return credentialPrefix + strings.Join([]string{
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(tag),
		base64.RawURLEncoding.EncodeToString(ciphertext),
	}, "."), nil
}

// DecryptCredentialValue accepts both ZCode's encrypted values and plaintext
// values.  Plaintext support is important for migration, fixtures, and older
// local installations.  Decryption errors intentionally collapse to one safe
// error without echoing the input.
func (c CredentialCipher) DecryptCredentialValue(value string) (string, error) {
	if !strings.HasPrefix(value, credentialPrefix) {
		if strings.HasPrefix(value, "enc:") {
			return "", ErrCredentialDecrypt
		}
		return value, nil
	}
	if len(value) > maxCredentialValueBytes {
		return "", ErrCredentialDecrypt
	}

	parts := strings.Split(strings.TrimPrefix(value, credentialPrefix), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", ErrCredentialDecrypt
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(nonce) != credentialNonce {
		return "", ErrCredentialDecrypt
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(tag) != credentialTag {
		return "", ErrCredentialDecrypt
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(ciphertext) > maxCredentialValueBytes {
		return "", ErrCredentialDecrypt
	}

	block, err := aes.NewCipher(DeriveCredentialKey(c.secret))
	if err != nil {
		return "", ErrCredentialDecrypt
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, credentialNonce)
	if err != nil {
		return "", ErrCredentialDecrypt
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", ErrCredentialDecrypt
	}
	return string(plaintext), nil
}

// DecryptCredentialValue uses the current ZCode-compatible key.
func DecryptCredentialValue(value string) (string, error) {
	return NewCredentialCipher().DecryptCredentialValue(value)
}

// EncryptCredentialValue uses the current ZCode-compatible key.
func EncryptCredentialValue(plaintext string) (string, error) {
	return NewCredentialCipher().EncryptCredentialValue(plaintext)
}

// IsEncryptedCredentialValue reports whether a value asks for ZCode v1
// decryption.  It does not inspect or decode the secret-bearing payload.
func IsEncryptedCredentialValue(value string) bool {
	return strings.HasPrefix(value, credentialPrefix)
}
