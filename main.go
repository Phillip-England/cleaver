package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultAddr             = "0.0.0.0:5544"
	configPath              = "config/.env"
	defaultDBPath           = "../data/main.sqlite"
	sessionCookieName       = "cleaver_session"
	sessionLifetime         = 12 * time.Hour
	failureWindow           = 24 * time.Hour
	maxRecentFailures       = 5
	maxUploadBytes    int64 = 25 << 20
)

var (
	lockMagic   = []byte("CLEAVER1\n")
	bundleMagic = "CLEAVER-BUNDLE1\n"
)

//go:embed public
var publicFiles embed.FS

type config struct {
	AdminUsername string
	AdminPassword string
	SessionSecret []byte
	DBPath        string
}

type appServer struct {
	db     *sql.DB
	cfg    config
	public http.Handler
	now    func() time.Time
}

type registryKey struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Filename  string `json:"filename"`
	Token     string `json:"token"`
	CreatedAt int64  `json:"created_at"`
}

type lockHeader struct {
	Version      int      `json:"version"`
	Cipher       string   `json:"cipher"`
	KDF          string   `json:"kdf"`
	Nonce        string   `json:"nonce"`
	OriginalName string   `json:"original_name"`
	ShardIDs     []string `json:"shard_ids"`
}

type decodedLock struct {
	Header     lockHeader
	Prefix     []byte
	Ciphertext []byte
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "cleaver:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) > 0 && args[0] == "init" {
		return initApp(stdout)
	}

	flags := flag.NewFlagSet("cleaver", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	addr := flags.String("addr", defaultAddr, "listen address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return errors.New("usage: cleaver init | cleaver [-addr 0.0.0.0:5544]")
	}

	handler, err := appHandler()
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "cleaver running at %s\n", browserURL(*addr))
	return http.ListenAndServe(*addr, handler)
}

func initApp(stdout io.Writer) error {
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll("data", 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		secret := randomToken(32)
		env := "ADMIN_USERNAME=admin\nADMIN_PASSWORD=change-me-now\nSESSION_SECRET=" + secret + "\nDB_PATH=" + defaultDBPath + "\n"
		if err := os.WriteFile(configPath, []byte(env), 0o600); err != nil {
			return err
		}
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	fmt.Fprintf(stdout, "initialized %s and %s\n", configPath, cfg.DBPath)
	return nil
}

func appHandler() (http.Handler, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	public, err := staticHandler()
	if err != nil {
		db.Close()
		return nil, err
	}
	return &appServer{db: db, cfg: cfg, public: public, now: time.Now}, nil
}

func loadConfig() (config, error) {
	values, err := readEnvFile(configPath)
	if err != nil {
		return config{}, fmt.Errorf("read %s: %w; run `cleaver init` first", configPath, err)
	}
	secret := values["SESSION_SECRET"]
	if secret == "" {
		return config{}, errors.New("SESSION_SECRET is required")
	}
	dbPath := values["DB_PATH"]
	if dbPath == "" {
		dbPath = defaultDBPath
	}
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Clean(filepath.Join(filepath.Dir(configPath), dbPath))
	}
	cfg := config{
		AdminUsername: values["ADMIN_USERNAME"],
		AdminPassword: values["ADMIN_PASSWORD"],
		SessionSecret: []byte(secret),
		DBPath:        dbPath,
	}
	if cfg.AdminUsername == "" || cfg.AdminPassword == "" {
		return config{}, errors.New("ADMIN_USERNAME and ADMIN_PASSWORD are required")
	}
	return cfg, nil
}

func readEnvFile(path string) (map[string]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return values, nil
}

func openDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	var tokenColumn int
	rows, err := db.Query(`PRAGMA table_info(registry_keys)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notnull, &defaultValue, &pk); err != nil {
			rows.Close()
			db.Close()
			return nil, err
		}
		if name == "token" {
			tokenColumn = 1
		}
	}
	rows.Close()
	if tokenColumn == 0 {
		if _, err := db.Exec(`ALTER TABLE registry_keys ADD COLUMN token TEXT NOT NULL DEFAULT ''`); err != nil {
			db.Close()
			return nil, err
		}
		keyRows, err := db.Query(`SELECT id FROM registry_keys`)
		if err != nil {
			db.Close()
			return nil, err
		}
		var ids []int64
		for keyRows.Next() {
			var id int64
			if err := keyRows.Scan(&id); err != nil {
				keyRows.Close()
				db.Close()
				return nil, err
			}
			ids = append(ids, id)
		}
		keyRows.Close()
		for _, id := range ids {
			if _, err := db.Exec(`UPDATE registry_keys SET token = ? WHERE id = ?`, randomToken(24), id); err != nil {
				db.Close()
				return nil, err
			}
		}
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_registry_keys_token ON registry_keys(token)`); err != nil {
		db.Close()
		return nil, err
	}
	// Legacy releases persisted uploaded locks in these tables. Remove them on
	// every startup so the database can contain key material only.
	if _, err := db.Exec(`DROP TABLE IF EXISTS registry_locks; DROP TABLE IF EXISTS artifacts;`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS login_failures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  attempted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_failures_ip_time ON login_failures (ip, attempted_at);
CREATE TABLE IF NOT EXISTS unlock_failures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  attempted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_unlock_failures_ip_time ON unlock_failures (ip, attempted_at);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS registry_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  filename TEXT NOT NULL,
  data BLOB NOT NULL,
  token TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
`

func browserURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func staticHandler() (http.Handler, error) {
	root, err := fs.Sub(publicFiles, "public")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(root))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}

		if _, err := fs.Stat(root, path); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}

		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	}), nil
}

func (s *appServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/login":
		s.handleLogin(w, r)
	case r.URL.Path == "/logout":
		s.handleLogout(w, r)
	case strings.HasPrefix(r.URL.Path, "/key/"):
		s.handlePublicKey(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/key/"):
		s.handlePublicKeyAPI(w, r)
	case r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/"):
		if !s.requireSession(w, r) {
			return
		}
		s.handleAdmin(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/admin/"):
		if !s.requireSession(w, r) {
			return
		}
		s.handleAdminAPI(w, r)
	default:
		s.public.ServeHTTP(w, r)
	}
}

func (s *appServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.validSession(r) {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		renderLogin(w, "")
	case http.MethodPost:
		ip := clientIP(r)
		allowed, err := s.checkFailureLimit("login_failures", ip)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if !allowed {
			http.Error(w, "too many login attempts", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		usernameOK := subtleEqualString(r.FormValue("username"), s.cfg.AdminUsername)
		passwordOK := subtleEqualString(r.FormValue("password"), s.cfg.AdminPassword)
		if usernameOK && passwordOK {
			s.createSession(w)
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		banned, err := s.recordFailure("login_failures", ip)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if banned {
			http.Error(w, "too many login attempts", http.StatusForbidden)
			return
		}
		renderLogin(w, "Invalid username or password.")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *appServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		id, _ := splitSignedCookie(cookie.Value)
		if id != "" {
			s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *appServer) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	adminTemplate.Execute(w, nil)
}

func (s *appServer) publicKeyData(token string) (registryKey, []byte, error) {
	var key registryKey
	var data []byte
	err := s.db.QueryRow(`SELECT id, name, filename, token, created_at, data FROM registry_keys WHERE token = ?`, token).
		Scan(&key.ID, &key.Name, &key.Filename, &key.Token, &key.CreatedAt, &data)
	return key, data, err
}

func (s *appServer) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.Trim(strings.TrimPrefix(r.URL.Path, "/key/"), "/")
	key, _, err := s.publicKeyData(token)
	if err != nil {
		http.Error(w, "key not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	publicKeyTemplate.Execute(w, key)
}

func (s *appServer) handlePublicKeyAPI(w http.ResponseWriter, r *http.Request) {
	allowed, err := s.checkFailureLimit("unlock_failures", clientIP(r))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "too many unlock attempts", http.StatusForbidden)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/key/"), "/")
	token, action, ok := strings.Cut(path, "/")
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	key, keyData, err := s.publicKeyData(token)
	if err != nil {
		http.Error(w, "key not found", http.StatusNotFound)
		return
	}
	if action == "open" && r.Method == http.MethodPost {
		s.openPublicLock(w, r, keyData)
		return
	}
	if action == "relock" && r.Method == http.MethodPost {
		var req struct {
			PIN      string `json:"pin"`
			LockData string `json:"lock_data"`
			CSV      string `json:"csv"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		lockData, err := base64.StdEncoding.DecodeString(req.LockData)
		if err != nil {
			http.Error(w, "invalid lock", http.StatusBadRequest)
			return
		}
		_, name, err := unlockPair(lockData, keyData, req.PIN)
		if err != nil {
			s.recordFailure("unlock_failures", clientIP(r))
			http.Error(w, "unlock failed", http.StatusUnauthorized)
			return
		}
		updated, err := relockWithLockAndBundle([]byte(req.CSV), name, req.PIN, lockData, keyData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"name": outputName(name, ".lock"), "lock_data": base64.StdEncoding.EncodeToString(updated), "key": key.Name})
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (s *appServer) openPublicLock(w http.ResponseWriter, r *http.Request, keyData []byte) {
	form, files, ok := readMultipartInMemory(w, r)
	if !ok {
		return
	}
	lockData := files["lock"].Data
	if len(lockData) == 0 {
		http.Error(w, "lock file is required", http.StatusBadRequest)
		return
	}
	plain, name, err := unlockPair(lockData, keyData, form["pin"])
	if err != nil {
		s.recordFailure("unlock_failures", clientIP(r))
		http.Error(w, "unlock failed", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"name": name, "data": base64.StdEncoding.EncodeToString(plain)})
}

func (s *appServer) handleAdminAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/")
	switch {
	case path == "keys" && r.Method == http.MethodGet:
		s.listArtifacts(w, r)
	case strings.HasPrefix(path, "keys/") && strings.HasSuffix(path, "/download") && r.Method == http.MethodGet:
		s.downloadKey(w, r)
	case strings.HasPrefix(path, "keys/") && r.Method == http.MethodDelete:
		s.deleteKey(w, r)
	case path == "encrypt" && r.Method == http.MethodPost:
		s.encryptArtifact(w, r)
	case path == "open" && r.Method == http.MethodPost:
		s.openLock(w, r)
	case path == "relock" && r.Method == http.MethodPost:
		s.relockArtifact(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (s *appServer) listArtifacts(w http.ResponseWriter, r *http.Request) {
	keyRows, err := s.db.Query(`SELECT id, name, filename, token, created_at FROM registry_keys ORDER BY created_at DESC, id DESC`)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer keyRows.Close()
	keys := []registryKey{}
	for keyRows.Next() {
		var item registryKey
		if err := keyRows.Scan(&item.ID, &item.Name, &item.Filename, &item.Token, &item.CreatedAt); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		keys = append(keys, item)
	}
	writeJSON(w, map[string]any{"keys": keys})
}

func keyIDFromPath(path string) (int64, error) {
	part := strings.TrimSuffix(strings.TrimPrefix(path, "/api/admin/keys/"), "/download")
	return strconv.ParseInt(strings.Trim(part, "/"), 10, 64)
}

func (s *appServer) keyData(id int64) (string, string, []byte, error) {
	var name, filename string
	var data []byte
	err := s.db.QueryRow(`SELECT name, filename, data FROM registry_keys WHERE id = ?`, id).Scan(&name, &filename, &data)
	return name, filename, data, err
}

func (s *appServer) downloadKey(w http.ResponseWriter, r *http.Request) {
	id, err := keyIDFromPath(r.URL.Path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	name, filename, data, err := s.keyData(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if filename == "" {
		filename = name + ".key"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFilename(filename)+`"`)
	w.Write(data)
}

func (s *appServer) deleteKey(w http.ResponseWriter, r *http.Request) {
	id, err := keyIDFromPath(r.URL.Path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.db.Exec(`DELETE FROM registry_keys WHERE id = ?`, id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *appServer) encryptArtifact(w http.ResponseWriter, r *http.Request) {
	name, filename, pin, data, ok := s.readMultipartAsset(w, r)
	if !ok {
		return
	}
	if err := validatePin(pin); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if name == "" {
		name = filename
	}
	if !strings.HasSuffix(strings.ToLower(filename), ".csv") {
		http.Error(w, "only CSV files can be locked", http.StatusBadRequest)
		return
	}
	locked, bundle, err := encryptWithPIN(data, filename, pin)
	if err != nil {
		http.Error(w, "encrypt failed", http.StatusInternalServerError)
		return
	}
	now := s.now().Unix()
	keyFilename := outputName(filename, ".key")
	token := randomToken(24)
	result, err := s.db.Exec(`INSERT INTO registry_keys (name, filename, data, token, created_at) VALUES (?, ?, ?, ?, ?)`, name, keyFilename, bundle, token, now)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	keyID, _ := result.LastInsertId()
	writeJSON(w, map[string]any{
		"key_id": keyID, "key_name": keyFilename, "lock_name": outputName(filename, ".lock"),
		"lock_data": base64.StdEncoding.EncodeToString(locked), "public_url": "/key/" + token,
	})
}

func (s *appServer) openLock(w http.ResponseWriter, r *http.Request) {
	form, files, ok := readMultipartInMemory(w, r)
	if !ok {
		return
	}
	keyID, err := strconv.ParseInt(form["key_id"], 10, 64)
	if err != nil {
		http.Error(w, "choose a key", http.StatusBadRequest)
		return
	}
	lockData := files["lock"].Data
	if len(lockData) == 0 {
		http.Error(w, "lock file is required", http.StatusBadRequest)
		return
	}
	_, _, keyData, err := s.keyData(keyID)
	if err != nil {
		http.Error(w, "key not found", http.StatusNotFound)
		return
	}
	plain, name, err := unlockPair(lockData, keyData, form["pin"])
	if err != nil {
		http.Error(w, "unlock failed", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"name": name, "data": base64.StdEncoding.EncodeToString(plain)})
}

func (s *appServer) relockArtifact(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID    int64  `json:"key_id"`
		LockData string `json:"lock_data"`
		PIN      string `json:"pin"`
		CSV      string `json:"csv"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.KeyID == 0 || req.LockData == "" {
		http.Error(w, "key and lock are required", http.StatusBadRequest)
		return
	}
	lockData, err := base64.StdEncoding.DecodeString(req.LockData)
	if err != nil {
		http.Error(w, "invalid lock data", http.StatusBadRequest)
		return
	}
	_, _, keyData, err := s.keyData(req.KeyID)
	if err != nil {
		http.Error(w, "key not found", http.StatusNotFound)
		return
	}
	_, name, err := unlockPair(lockData, keyData, req.PIN)
	if err != nil {
		http.Error(w, "unlock failed", http.StatusUnauthorized)
		return
	}
	updated, err := relockWithLockAndBundle([]byte(req.CSV), name, req.PIN, lockData, keyData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"name": outputName(name, ".lock"), "lock_data": base64.StdEncoding.EncodeToString(updated)})
}

func (s *appServer) readMultipartAsset(w http.ResponseWriter, r *http.Request) (string, string, string, []byte, bool) {
	form, files, ok := readMultipartInMemory(w, r)
	if !ok {
		return "", "", "", nil, false
	}
	file := files["file"]
	if len(file.Data) == 0 {
		http.Error(w, "file is required", http.StatusBadRequest)
		return "", "", "", nil, false
	}
	name := strings.TrimSpace(form["name"])
	if name == "" {
		name = file.Filename
	}
	if name == "" {
		name = "artifact"
	}
	return name, safeFilename(file.Filename), form["pin"], file.Data, true
}

type memoryUpload struct {
	Filename string
	Data     []byte
}

// readMultipartInMemory deliberately avoids ParseMultipartForm, which may use
// temporary files. Uploaded bytes live only in request-scoped memory.
func readMultipartInMemory(w http.ResponseWriter, r *http.Request) (map[string]string, map[string]memoryUpload, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "invalid upload", http.StatusBadRequest)
		return nil, nil, false
	}
	fields := map[string]string{}
	files := map[string]memoryUpload{}
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return nil, nil, false
		}
		data, err := io.ReadAll(part)
		part.Close()
		if err != nil {
			http.Error(w, "upload is too large or invalid", http.StatusBadRequest)
			return nil, nil, false
		}
		if part.FileName() == "" {
			fields[part.FormName()] = string(data)
		} else {
			files[part.FormName()] = memoryUpload{Filename: safeFilename(part.FileName()), Data: data}
		}
	}
	return fields, files, true
}

func (s *appServer) checkFailureLimit(table, ip string) (bool, error) {
	cutoff := s.now().Add(-failureWindow).Unix()
	if _, err := s.db.Exec(`DELETE FROM `+table+` WHERE attempted_at < ?`, cutoff); err != nil {
		return false, err
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM `+table+` WHERE ip = ? AND attempted_at >= ?`, ip, cutoff).Scan(&count); err != nil {
		return false, err
	}
	return count < maxRecentFailures, nil
}

func (s *appServer) recordFailure(table, ip string) (bool, error) {
	now := s.now().Unix()
	cutoff := s.now().Add(-failureWindow).Unix()
	if _, err := s.db.Exec(`INSERT INTO `+table+` (ip, attempted_at) VALUES (?, ?)`, ip, now); err != nil {
		return false, err
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM `+table+` WHERE ip = ? AND attempted_at >= ?`, ip, cutoff).Scan(&count); err != nil {
		return false, err
	}
	return count >= maxRecentFailures, nil
}

func (s *appServer) createSession(w http.ResponseWriter) {
	id := randomToken(32)
	expires := s.now().Add(sessionLifetime)
	s.db.Exec(`INSERT INTO sessions (id, expires_at) VALUES (?, ?)`, id, expires.Unix())
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    s.signCookie(id),
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(sessionLifetime.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *appServer) requireSession(w http.ResponseWriter, r *http.Request) bool {
	if s.validSession(r) {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	return false
}

func (s *appServer) validSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	id, sig := splitSignedCookie(cookie.Value)
	if id == "" || sig == "" || !hmac.Equal([]byte(sig), []byte(s.cookieSignature(id))) {
		return false
	}
	var expires int64
	if err := s.db.QueryRow(`SELECT expires_at FROM sessions WHERE id = ?`, id).Scan(&expires); err != nil {
		return false
	}
	if expires <= s.now().Unix() {
		s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
		return false
	}
	return true
}

func (s *appServer) signCookie(id string) string {
	return id + "." + s.cookieSignature(id)
}

func (s *appServer) cookieSignature(id string) string {
	mac := hmac.New(sha256.New, s.cfg.SessionSecret)
	mac.Write([]byte(id))
	return hex.EncodeToString(mac.Sum(nil))
}

func splitSignedCookie(value string) (string, string) {
	id, sig, ok := strings.Cut(value, ".")
	if !ok {
		return "", ""
	}
	return id, sig
}

func renderLogin(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTemplate.Execute(w, map[string]string{"Message": message})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func subtleEqualString(left, right string) bool {
	return hmac.Equal([]byte(left), []byte(right))
}

func safeFilename(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "artifact"
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == '"' || r == '\\' || r == '/' {
			return -1
		}
		return r
	}, name)
}

func outputName(name, ext string) string {
	clean := safeFilename(name)
	dot := strings.LastIndex(clean, ".")
	if dot > 0 {
		return clean[:dot] + ext
	}
	return clean + ext
}

func validatePin(pin string) error {
	if pin == "" {
		return errors.New("PIN must not be empty")
	}
	for _, char := range pin {
		if char < '0' || char > '9' {
			return errors.New("PIN must contain only digits 0-9")
		}
	}
	return nil
}

func encryptWithPIN(plain []byte, originalName, pin string) ([]byte, []byte, error) {
	shards := map[byte][]byte{}
	shardIDs := make([]string, 10)
	for digit := byte('0'); digit <= '9'; digit++ {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, nil, err
		}
		shards[digit] = key
		shardIDs[digit-'0'] = randomToken(12)
	}
	key := combineShards(shards, pin)
	locked, err := lockWithKey(plain, originalName, key, shardIDs)
	if err != nil {
		return nil, nil, err
	}
	bundle, err := encodeBundle(shards, shardIDs)
	return locked, bundle, err
}

func relockWithLockAndBundle(plain []byte, originalName, pin string, lockData, bundle []byte) ([]byte, error) {
	decoded, err := decodeLock(lockData)
	if err != nil {
		return nil, err
	}
	shardsByID, err := decodeBundle(bundle)
	if err != nil {
		return nil, err
	}
	shards := map[byte][]byte{}
	for digit, id := range decoded.Header.ShardIDs {
		value := shardsByID[id]
		if len(value) != 32 {
			return nil, errors.New("bundle does not belong to selected lock")
		}
		shards[byte('0'+digit)] = value
	}
	return lockWithKey(plain, originalName, combineShards(shards, pin), decoded.Header.ShardIDs)
}

func lockWithKey(plain []byte, originalName string, key []byte, shardIDs []string) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := lockHeader{
		Version:      1,
		Cipher:       "AES-256-GCM",
		KDF:          "pin-sha256",
		Nonce:        base64.RawURLEncoding.EncodeToString(nonce),
		OriginalName: safeFilename(originalName),
		ShardIDs:     shardIDs,
	}
	prefix, err := encodePrefix(header)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plain, prefix)
	return append(prefix, ciphertext...), nil
}

func unlockPair(left, right []byte, pin string) ([]byte, string, error) {
	lockBytes, bundleBytes := left, right
	if bytes.HasPrefix(right, lockMagic) {
		lockBytes, bundleBytes = right, left
	}
	decoded, err := decodeLock(lockBytes)
	if err != nil {
		return nil, "", err
	}
	shardsByID, err := decodeBundle(bundleBytes)
	if err != nil {
		return nil, "", err
	}
	shards := map[byte][]byte{}
	for digit, id := range decoded.Header.ShardIDs {
		value := shardsByID[id]
		if len(value) != 32 {
			return nil, "", errors.New("bundle does not belong to selected lock")
		}
		shards[byte('0'+digit)] = value
	}
	key := combineShards(shards, pin)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(decoded.Header.Nonce)
	if err != nil {
		return nil, "", err
	}
	plain, err := aead.Open(nil, nonce, decoded.Ciphertext, decoded.Prefix)
	if err != nil {
		return nil, "", err
	}
	return plain, decoded.Header.OriginalName, nil
}

func decodeLock(data []byte) (decodedLock, error) {
	if len(data) < len(lockMagic)+4 || !bytes.Equal(data[:len(lockMagic)], lockMagic) {
		return decodedLock{}, errors.New("not a Cleaver lock file")
	}
	headerLen := binary.BigEndian.Uint32(data[len(lockMagic) : len(lockMagic)+4])
	headerStart := len(lockMagic) + 4
	headerEnd := headerStart + int(headerLen)
	if headerEnd > len(data) {
		return decodedLock{}, errors.New("truncated lock header")
	}
	var header lockHeader
	if err := json.Unmarshal(data[headerStart:headerEnd], &header); err != nil {
		return decodedLock{}, err
	}
	if header.Version != 1 || header.Cipher != "AES-256-GCM" || header.KDF != "pin-sha256" || len(header.ShardIDs) != 10 {
		return decodedLock{}, errors.New("unsupported lock file")
	}
	return decodedLock{Header: header, Prefix: data[:headerEnd], Ciphertext: data[headerEnd:]}, nil
}

func encodePrefix(header lockHeader) ([]byte, error) {
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(lockMagic)+4+len(headerBytes))
	copy(out, lockMagic)
	binary.BigEndian.PutUint32(out[len(lockMagic):len(lockMagic)+4], uint32(len(headerBytes)))
	copy(out[len(lockMagic)+4:], headerBytes)
	return out, nil
}

func combineShards(shards map[byte][]byte, pin string) []byte {
	hash := sha256.New()
	for i := range pin {
		hash.Write(shards[pin[i]])
	}
	return hash.Sum(nil)
}

func encodeBundle(shards map[byte][]byte, shardIDs []string) ([]byte, error) {
	type entry struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	entries := make([]entry, 10)
	for digit := 0; digit < 10; digit++ {
		entries[digit] = entry{ID: shardIDs[digit], Value: base64.RawURLEncoding.EncodeToString(shards[byte('0'+digit)])}
	}
	for i := range entries {
		j := i
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		if len(entries)-i > 0 {
			j = i + int(b[0])%(len(entries)-i)
		}
		entries[i], entries[j] = entries[j], entries[i]
	}
	body, err := json.Marshal(struct {
		Version int     `json:"version"`
		Entries []entry `json:"entries"`
	}{Version: 1, Entries: entries})
	if err != nil {
		return nil, err
	}
	return append([]byte(bundleMagic), body...), nil
}

func decodeBundle(data []byte) (map[string][]byte, error) {
	if !bytes.HasPrefix(data, []byte(bundleMagic)) {
		return nil, errors.New("not a Cleaver key bundle")
	}
	var bundle struct {
		Version int `json:"version"`
		Entries []struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data[len(bundleMagic):], &bundle); err != nil {
		return nil, err
	}
	if bundle.Version != 1 || len(bundle.Entries) != 10 {
		return nil, errors.New("unsupported key bundle")
	}
	out := map[string][]byte{}
	for _, entry := range bundle.Entries {
		value, err := base64.RawURLEncoding.DecodeString(entry.Value)
		if err != nil || len(value) != 32 || entry.ID == "" {
			return nil, errors.New("corrupted key bundle")
		}
		out[entry.ID] = value
	}
	if len(out) != 10 {
		return nil, errors.New("corrupted key bundle")
	}
	return out, nil
}

func randomToken(bytesLen int) string {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cleaver Login</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <main class="app-shell admin-auth">
    <form class="panel form-panel login-panel" method="post" action="/login">
      <h2>Admin Login</h2>
      {{if .Message}}<div class="status err">{{.Message}}</div>{{end}}
      <div class="field"><label for="username">Username</label><input class="input" id="username" name="username" autocomplete="username" required></div>
      <div class="field"><label for="password">Password</label><input class="input" id="password" name="password" type="password" autocomplete="current-password" required></div>
      <button class="primary full" type="submit">Log in</button>
    </form>
  </main>
</body>
</html>`))

var adminTemplate = template.Must(template.New("admin").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cleaver Admin</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <header class="site-header">
    <div class="app-shell header-inner">
      <a class="brand admin-brand" href="/admin"><span class="brand-mark">C</span><span>Cleaver Admin</span></a>
      <nav class="site-nav" aria-label="Admin navigation">
        <button class="tab active" data-admin-tab="registry" type="button">Keys</button>
        <button class="tab" data-admin-tab="encrypt" type="button">New lock</button>
        <button class="tab" data-admin-tab="unlock" type="button">Open a lock</button>
      </nav>
      <a class="nav-cta" href="/logout">Logout</a>
    </div>
  </header>
  <main class="app-shell site-main admin-main">
    <section class="screen active" id="admin-registry">
      <div class="page-head"><h2>Your keys</h2><p>Keys stay safely in this portal. Lock files are never stored here.</p></div>
      <div class="artifact-list" id="keyList"></div>
    </section>
    <section class="screen" id="admin-encrypt">
      <div class="page-head"><h2>Create a lock and key</h2><p>Upload a CSV and choose a PIN. The key is saved here; you download and manage the encrypted lock file.</p></div>
      <form class="panel form-panel" id="adminEncryptForm">
        <div class="field"><label for="encryptName">Key name</label><input class="input" id="encryptName" name="name" placeholder="Project key"></div>
        <div class="field"><label for="encryptFile">CSV file</label><input class="input" id="encryptFile" name="file" type="file" accept=".csv,text/csv" required></div>
        <div class="field"><label for="encryptPin">PIN</label><input class="input" id="encryptPin" name="pin" inputmode="numeric" pattern="[0-9]*" autocomplete="off" required></div>
        <button class="primary" type="submit">Create lock and save key</button>
        <div class="status" id="adminEncryptStatus"></div>
      </form>
      <div class="panel lock-created" id="lockCreated" hidden></div>
    </section>
    <section class="screen" id="admin-unlock">
      <div class="page-head"><h2>Open a lock</h2><p>Choose its saved key, upload the lock file, and enter the PIN. After editing, download a new lock file.</p></div>
      <form class="panel form-panel" id="unlockForm">
        <div class="edit-credential-grid">
          <div class="field"><label for="keySelect">Saved key</label><select class="input" id="keySelect" required></select></div>
          <div class="field"><label for="lockFile">Lock file</label><input class="input" id="lockFile" type="file" accept=".lock" required></div>
        </div>
        <div class="field"><label for="unlockPin">PIN</label><input class="input" id="unlockPin" inputmode="numeric" pattern="[0-9]*" autocomplete="off" required></div>
        <div class="actions"><button class="primary" type="submit">Unlock and edit</button><button class="secondary" id="decryptDownload" type="button">Download CSV</button></div>
        <div class="status" id="unlockStatus"></div>
      </form>
      <div class="text-workspace" id="adminWorkspace" hidden>
        <div class="editor-toolbar"><div><h3 id="adminEditorTitle">Spreadsheet editor</h3><div class="hint" id="adminEditorMeta"></div></div><button class="primary" id="adminRelock" type="button">Download new lock</button></div>
        <div class="sheet-actions"><button class="secondary" id="adminAddRow" type="button">Add row</button><button class="secondary" id="adminAddColumn" type="button">Add column</button></div>
        <div class="spreadsheet-scroll"><table class="spreadsheet" id="adminGrid"></table></div>
        <div class="status" id="relockStatus"></div>
      </div>
    </section>
  </main>
  <script src="/admin.js" defer></script>
</body>
</html>`))

var publicKeyTemplate = template.Must(template.New("public-key").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{.Name}} · Cleaver</title><link rel="stylesheet" href="/styles.css"></head>
<body data-key-token="{{.Token}}">
  <header class="site-header"><div class="app-shell header-inner"><a class="brand admin-brand" href="/"><span class="brand-mark">C</span><span>Cleaver</span></a></div></header>
  <main class="app-shell site-main admin-main">
    <div class="page-head"><p class="eyebrow">Public key</p><h2>{{.Name}}</h2><p>Upload your lock and enter its PIN. Your lock and decrypted contents are processed only for this request and are not saved.</p></div>
    <form class="panel form-panel" id="publicUnlockForm">
      <div class="field"><label for="publicLockFile">Lock file</label><label class="dropzone" id="publicDropzone" for="publicLockFile"><span>Drop your lock file here</span><small>or choose a file</small></label><input class="file-input" id="publicLockFile" type="file" accept=".lock" required><div class="file-meta" id="publicLockMeta">No lock file selected.</div></div>
      <div class="field"><label for="publicPin">PIN</label><input class="input" id="publicPin" inputmode="numeric" pattern="[0-9]*" autocomplete="off" required></div>
      <button class="primary" type="submit">Unlock and edit</button><div class="status" id="publicStatus"></div>
    </form>
    <div class="text-workspace" id="publicWorkspace" hidden>
      <div class="editor-toolbar"><div><h3 id="publicEditorTitle">Spreadsheet editor</h3><div class="hint" id="publicEditorMeta"></div></div><button class="primary" id="publicRelock" type="button">Download new lock</button></div>
      <div class="sheet-actions"><button class="secondary" id="publicAddRow" type="button">Add row</button><button class="secondary" id="publicAddColumn" type="button">Add column</button></div>
      <div class="spreadsheet-scroll"><table class="spreadsheet" id="publicGrid"></table></div><div class="status" id="publicRelockStatus"></div>
    </div>
  </main>
  <script src="/public-key.js" defer></script>
</body></html>`))
