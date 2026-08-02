package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedKeyRoundTrip(t *testing.T) {
	plain := []byte("account,balance\nchecking,42\n")

	spec, keyText, err := keyForLock("")
	if err != nil {
		t.Fatal(err)
	}
	locked, err := lockBytes(plain, spec, "")
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := unlockBytes(locked, keyText)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestPassphraseRoundTrip(t *testing.T) {
	plain := []byte("secret data")
	spec := keySpec{passphrase: "correct horse battery staple"}

	locked, err := lockBytes(plain, spec, "")
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := unlockBytes(locked, spec.passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
	if _, _, err := unlockBytes(locked, "wrong key"); err == nil {
		t.Fatal("expected wrong key to fail")
	}
}

func TestCLIWritesExpectedFiles(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "somefile.csv")
	if err := os.WriteFile(input, []byte("a,b\n1,2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := run([]string{"lock", input}, &out, &out); err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(dir, "somefile.lock")
	keyPath := filepath.Join(dir, "somefile.key")
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(keyBytes)), keyPrefix) {
		t.Fatalf("key file did not contain %s token", keyPrefix)
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"unlock", lockPath, keyPath}, &out, &out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "a,b\n1,2\n" {
		t.Fatalf("unexpected unlocked contents: %q", got)
	}
}
