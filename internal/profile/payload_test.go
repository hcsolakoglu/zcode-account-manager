package profile

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSealOpenPayloadRoundTripAndPurposeBinding(t *testing.T) {
	root := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	store, err := NewStoreWithKey(root, key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"journal":"refresh-secret","telemetry":"opaque"}`)
	sealed, err := store.SealPayload("transaction-journal", plaintext)
	if err != nil {
		t.Fatalf("SealPayload: %v", err)
	}
	if bytes.Contains(sealed, plaintext) || strings.Contains(string(sealed), "refresh-secret") {
		t.Fatal("sealed payload contains plaintext")
	}
	opened, err := store.OpenPayload("transaction-journal", sealed)
	if err != nil {
		t.Fatalf("OpenPayload: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened payload = %q", opened)
	}
	if _, err := store.OpenPayload("backup", sealed); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong purpose error = %v", err)
	}
	opened[0] ^= 1
	openedAgain, err := store.OpenPayload("transaction-journal", sealed)
	if err != nil || !bytes.Equal(openedAgain, plaintext) {
		t.Fatalf("returned plaintext aliases sealed state: err=%v payload=%q", err, openedAgain)
	}
}

func TestSealOpenPayloadWrongKeyAndTamper(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	store, err := NewStoreWithKey(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := store.SealPayload("backup.credentials", []byte("credential-secret"))
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := NewStoreWithKey(t.TempDir(), []byte("abcdefghijklmnopqrstuvwxyzABCDEF"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.OpenPayload("backup.credentials", sealed); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key error = %v", err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := store.OpenPayload("backup.credentials", sealed); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tamper error = %v", err)
	}
}

func TestSealOpenPayloadPurposeAndSizeValidation(t *testing.T) {
	store, err := NewStoreWithKey(t.TempDir(), []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []string{"", " ", "../journal", "bad\\purpose", strings.Repeat("x", maxPurposeBytes+1)} {
		if _, err := store.SealPayload(purpose, []byte("payload")); !errors.Is(err, ErrInvalidPurpose) {
			t.Errorf("purpose %q error = %v", purpose, err)
		}
	}
	tooLarge := make([]byte, int(MaxPayloadBytes)+1)
	if _, err := store.SealPayload("journal", tooLarge); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversize seal error = %v", err)
	}
	if _, err := store.OpenPayload("journal", make([]byte, int(MaxSealedPayloadBytes)+1)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversize open error = %v", err)
	}
	if _, err := store.OpenPayload("journal", []byte("not-a-payload")); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("malformed open error = %v", err)
	}
}
