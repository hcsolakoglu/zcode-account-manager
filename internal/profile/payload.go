package profile

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	payloadFileVersion = byte(1)
	payloadHeaderLen   = 8 + 1 + chacha20poly1305.NonceSizeX
	// MaxPayloadBytes bounds journal/backup payloads before encryption and
	// before the authenticated decrypt allocates plaintext memory.
	MaxPayloadBytes       int64 = 16 << 20
	MaxSealedPayloadBytes       = payloadHeaderLen + MaxPayloadBytes + chacha20poly1305.Overhead
	maxPurposeBytes             = 96
)

var payloadMagic = []byte{'Z', 'C', 'O', 'D', 'E', 'P', 'A', 'Y'}

// SealPayload encrypts an opaque journal or backup payload with the store's
// master key. The purpose is authenticated as associated data, so a sealed
// transaction journal cannot be replayed as a backup (or vice versa).
func (s *Store) SealPayload(purpose string, plaintext []byte) ([]byte, error) {
	if err := validatePurpose(purpose); err != nil {
		return nil, err
	}
	if int64(len(plaintext)) > MaxPayloadBytes {
		return nil, ErrPayloadTooLarge
	}
	key, err := s.masterKey()
	if err != nil {
		return nil, err
	}
	defer clearBytes(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalidKey
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate payload nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, payloadAAD(purpose))
	sealed := make([]byte, 0, payloadHeaderLen+len(ciphertext))
	sealed = append(sealed, payloadMagic...)
	sealed = append(sealed, payloadFileVersion)
	sealed = append(sealed, nonce...)
	sealed = append(sealed, ciphertext...)
	if int64(len(sealed)) > MaxSealedPayloadBytes {
		return nil, ErrPayloadTooLarge
	}
	return sealed, nil
}

// OpenPayload authenticates and decrypts a payload previously sealed for the
// same purpose. Wrong purposes, wrong keys, malformed headers, and tampering
// never return plaintext and are reported as authentication/corruption errors.
func (s *Store) OpenPayload(purpose string, sealed []byte) ([]byte, error) {
	if err := validatePurpose(purpose); err != nil {
		return nil, err
	}
	if len(sealed) < payloadHeaderLen+chacha20poly1305.Overhead {
		return nil, ErrCorrupt
	}
	if int64(len(sealed)) > MaxSealedPayloadBytes {
		return nil, ErrPayloadTooLarge
	}
	if !bytes.Equal(sealed[:len(payloadMagic)], payloadMagic) || sealed[len(payloadMagic)] != payloadFileVersion {
		return nil, ErrCorrupt
	}
	key, err := s.masterKey()
	if err != nil {
		return nil, err
	}
	defer clearBytes(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalidKey
	}
	nonceStart := len(payloadMagic) + 1
	nonceEnd := nonceStart + chacha20poly1305.NonceSizeX
	plaintext, err := aead.Open(nil, sealed[nonceStart:nonceEnd], sealed[nonceEnd:], payloadAAD(purpose))
	if err != nil {
		return nil, ErrAuthentication
	}
	if int64(len(plaintext)) > MaxPayloadBytes {
		return nil, ErrPayloadTooLarge
	}
	return append([]byte(nil), plaintext...), nil
}

func validatePurpose(purpose string) error {
	if purpose == "" || len(purpose) > maxPurposeBytes || purpose != strings.TrimSpace(purpose) || purpose == "." || purpose == ".." || strings.Contains(purpose, "..") {
		return ErrInvalidPurpose
	}
	for _, r := range purpose {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("-_.:/", r) {
			continue
		}
		return ErrInvalidPurpose
	}
	return nil
}

func payloadAAD(purpose string) []byte {
	const prefix = "zcode-auth/payload/v1/"
	result := make([]byte, 0, len(prefix)+len(purpose))
	result = append(result, prefix...)
	result = append(result, purpose...)
	return result
}
