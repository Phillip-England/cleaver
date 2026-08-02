package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	magic          = "CLEAVER1\n"
	keyPrefix      = "clv1:"
	headerLenBytes = 4

	kdfNone     = "none"
	kdfArgon2ID = "argon2id"
)

type lockHeader struct {
	Version      int    `json:"version"`
	Cipher       string `json:"cipher"`
	KDF          string `json:"kdf"`
	Salt         string `json:"salt,omitempty"`
	Nonce        string `json:"nonce"`
	OriginalName string `json:"original_name,omitempty"`
}

type keySpec struct {
	bytes      []byte
	passphrase string
	generated  bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "cleaver:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("missing command")
	}

	switch args[0] {
	case "lock":
		return runLock(args[1:], stdout)
	case "unlock":
		return runUnlock(args[1:], stdout)
	case "-h", "--help", "help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runLock(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	customKey := fs.String("key", "", "passphrase or clv1 key token")
	if err := fs.Parse(moveFlagsFirst(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: cleaver lock <file> [--key <key>]")
	}

	inputPath := fs.Arg(0)
	input, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	spec, keyText, err := keyForLock(*customKey)
	if err != nil {
		return err
	}

	locked, err := lockBytes(input, spec, filepath.Base(inputPath))
	if err != nil {
		return err
	}

	lockPath := outputPath(inputPath, ".lock")
	if err := writeNewFile(lockPath, locked, 0o600); err != nil {
		return err
	}

	if spec.generated {
		keyPath := outputPath(inputPath, ".key")
		if err := writeNewFile(keyPath, []byte(keyText+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "created %s\ncreated %s\n", lockPath, keyPath)
		return nil
	}

	fmt.Fprintf(stdout, "created %s\n", lockPath)
	return nil
}

func runUnlock(args []string, stdout io.Writer) error {
	if len(args) != 2 {
		return errors.New("usage: cleaver unlock <file.lock> <key-file-or-key>")
	}

	lockPath := args[0]
	locked, err := os.ReadFile(lockPath)
	if err != nil {
		return err
	}

	keyText, err := readKeyArg(args[1])
	if err != nil {
		return err
	}

	plain, header, err := unlockBytes(locked, strings.TrimSpace(keyText))
	if err != nil {
		return err
	}

	outPath := unlockOutputPath(lockPath, header.OriginalName)
	if err := writeNewFile(outPath, plain, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "created %s\n", outPath)
	return nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  cleaver lock <file> [--key <key>]
  cleaver unlock <file.lock> <key-file-or-key>

Generated keys are written beside the lock file as clv1 tokens. Custom keys are
accepted, but long random keys are strongly recommended.`)
}

func keyForLock(custom string) (keySpec, string, error) {
	if custom == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return keySpec{}, "", err
		}
		token := keyPrefix + base64.RawURLEncoding.EncodeToString(key)
		return keySpec{bytes: key, generated: true}, token, nil
	}

	if key, ok, err := parseRawKey(custom); ok || err != nil {
		return keySpec{bytes: key}, custom, err
	}

	return keySpec{passphrase: custom}, custom, nil
}

func lockBytes(plain []byte, spec keySpec, originalName string) ([]byte, error) {
	var key []byte
	header := lockHeader{
		Version:      1,
		Cipher:       "AES-256-GCM",
		Nonce:        mustRandomBase64(12),
		OriginalName: originalName,
	}

	if len(spec.bytes) > 0 {
		header.KDF = kdfNone
		key = spec.bytes
	} else {
		header.KDF = kdfArgon2ID
		header.Salt = mustRandomBase64(16)
		salt, err := base64.RawURLEncoding.DecodeString(header.Salt)
		if err != nil {
			return nil, err
		}
		key = deriveKey(spec.passphrase, salt)
	}

	nonce, err := base64.RawURLEncoding.DecodeString(header.Nonce)
	if err != nil {
		return nil, err
	}

	block, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	prefix, err := encodePrefix(headerBytes)
	if err != nil {
		return nil, err
	}

	ciphertext := block.Seal(nil, nonce, plain, prefix)
	return append(prefix, ciphertext...), nil
}

func unlockBytes(locked []byte, keyText string) ([]byte, lockHeader, error) {
	header, prefix, ciphertext, err := decodeLock(locked)
	if err != nil {
		return nil, header, err
	}

	var key []byte
	switch header.KDF {
	case kdfNone:
		raw, ok, err := parseRawKey(keyText)
		if err != nil {
			return nil, header, err
		}
		if !ok {
			return nil, header, errors.New("this lock requires a clv1 raw key token")
		}
		key = raw
	case kdfArgon2ID:
		salt, err := base64.RawURLEncoding.DecodeString(header.Salt)
		if err != nil {
			return nil, header, err
		}
		key = deriveKey(keyText, salt)
	default:
		return nil, header, fmt.Errorf("unsupported kdf %q", header.KDF)
	}

	nonce, err := base64.RawURLEncoding.DecodeString(header.Nonce)
	if err != nil {
		return nil, header, err
	}
	block, err := newGCM(key)
	if err != nil {
		return nil, header, err
	}

	plain, err := block.Open(nil, nonce, ciphertext, prefix)
	if err != nil {
		return nil, header, errors.New("unlock failed: wrong key or corrupted lock file")
	}
	return plain, header, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
}

func parseRawKey(text string) ([]byte, bool, error) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, keyPrefix) {
		return nil, false, nil
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(text, keyPrefix))
	if err != nil {
		return nil, true, err
	}
	if len(key) != 32 {
		return nil, true, fmt.Errorf("clv1 key must decode to 32 bytes, got %d", len(key))
	}
	return key, true, nil
}

func decodeLock(data []byte) (lockHeader, []byte, []byte, error) {
	var header lockHeader
	if len(data) < len(magic)+headerLenBytes || string(data[:len(magic)]) != magic {
		return header, nil, nil, errors.New("not a cleaver lock file")
	}

	headerLen := binary.BigEndian.Uint32(data[len(magic) : len(magic)+headerLenBytes])
	headerStart := len(magic) + headerLenBytes
	headerEnd := headerStart + int(headerLen)
	if headerEnd > len(data) {
		return header, nil, nil, errors.New("truncated lock header")
	}

	if err := json.Unmarshal(data[headerStart:headerEnd], &header); err != nil {
		return header, nil, nil, err
	}
	if header.Version != 1 {
		return header, nil, nil, fmt.Errorf("unsupported lock version %d", header.Version)
	}
	if header.Cipher != "AES-256-GCM" {
		return header, nil, nil, fmt.Errorf("unsupported cipher %q", header.Cipher)
	}

	return header, data[:headerEnd], data[headerEnd:], nil
}

func encodePrefix(header []byte) ([]byte, error) {
	if len(header) > int(^uint32(0)) {
		return nil, errors.New("header too large")
	}
	out := make([]byte, len(magic)+headerLenBytes+len(header))
	copy(out, magic)
	binary.BigEndian.PutUint32(out[len(magic):len(magic)+headerLenBytes], uint32(len(header)))
	copy(out[len(magic)+headerLenBytes:], header)
	return out, nil
}

func mustRandomBase64(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func readKeyArg(arg string) (string, error) {
	if strings.HasPrefix(strings.TrimSpace(arg), keyPrefix) {
		return arg, nil
	}
	if b, err := os.ReadFile(arg); err == nil {
		return string(b), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return arg, nil
}

func outputPath(inputPath, ext string) string {
	dir := filepath.Dir(inputPath)
	name := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
	return filepath.Join(dir, name+ext)
}

func unlockOutputPath(lockPath, originalName string) string {
	dir := filepath.Dir(lockPath)
	if originalName != "" && filepath.Base(originalName) == originalName {
		return filepath.Join(dir, originalName)
	}
	base := filepath.Base(lockPath)
	if filepath.Ext(base) == ".lock" {
		base = strings.TrimSuffix(base, ".lock")
	}
	return filepath.Join(dir, base)
}

func moveFlagsFirst(args []string) []string {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--key" || arg == "-key" {
			flags = append(flags, arg)
			if i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--key=") || strings.HasPrefix(arg, "-key=") {
			flags = append(flags, arg)
			continue
		}
		positionals = append(positionals, arg)
	}
	return append(flags, positionals...)
}

func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
