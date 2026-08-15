package profile

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretToolKeyProviderUsesConcurrentWinner(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "secret-value")
	scriptPath := filepath.Join(dir, "secret-tool")
	script := `#!/bin/sh
set -eu
if [ "$1" = "lookup" ]; then
  if [ -f "$ZCODE_AUTH_TEST_SECRET_STATE" ]; then
    cat "$ZCODE_AUTH_TEST_SECRET_STATE"
    exit 0
  fi
  exit 1
fi
if [ "$1" = "store" ]; then
  cat >/dev/null
  printf '%s\n' "$ZCODE_AUTH_TEST_WINNER" >"$ZCODE_AUTH_TEST_SECRET_STATE"
  exit 1
fi
exit 2
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	winner := bytes.Repeat([]byte{0x5a}, masterKeySize)
	t.Setenv("ZCODE_AUTH_TEST_SECRET_STATE", statePath)
	t.Setenv("ZCODE_AUTH_TEST_WINNER", base64.StdEncoding.EncodeToString(winner))
	provider := &SecretToolKeyProvider{Binary: scriptPath}
	got, err := provider.MasterKey(t.Context())
	if err != nil {
		t.Fatalf("MasterKey: %v", err)
	}
	if !bytes.Equal(got, winner) {
		t.Fatalf("winner key = %x, want %x", got, winner)
	}
}
