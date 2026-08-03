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
	"mime/multipart"
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

type artifact struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
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
CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  filename TEXT NOT NULL,
  content_type TEXT NOT NULL,
  data BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
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

func (s *appServer) handleAdminAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/")
	switch {
	case path == "artifacts" && r.Method == http.MethodGet:
		s.listArtifacts(w, r)
	case path == "artifacts" && r.Method == http.MethodPost:
		s.uploadArtifact(w, r)
	case strings.HasPrefix(path, "artifacts/") && strings.HasSuffix(path, "/download") && r.Method == http.MethodGet:
		s.downloadArtifact(w, r)
	case strings.HasPrefix(path, "artifacts/") && r.Method == http.MethodDelete:
		s.deleteArtifact(w, r)
	case path == "encrypt" && r.Method == http.MethodPost:
		s.encryptArtifact(w, r)
	case path == "decrypt" && r.Method == http.MethodPost:
		s.decryptArtifact(w, r)
	case path == "relock" && r.Method == http.MethodPost:
		s.relockArtifact(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (s *appServer) listArtifacts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`SELECT id, name, filename, length(data), created_at, updated_at FROM artifacts ORDER BY updated_at DESC, id DESC`)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	items := []artifact{}
	for rows.Next() {
		var item artifact
		if err := rows.Scan(&item.ID, &item.Name, &item.Filename, &item.Size, &item.CreatedAt, &item.UpdatedAt); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		items = append(items, item)
	}
	writeJSON(w, map[string]any{"artifacts": items})
}

func (s *appServer) uploadArtifact(w http.ResponseWriter, r *http.Request) {
	name, filename, contentType, data, ok := s.readMultipartAsset(w, r)
	if !ok {
		return
	}
	id, err := s.insertArtifact(name, filename, contentType, data)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"id": id})
}

func (s *appServer) downloadArtifact(w http.ResponseWriter, r *http.Request) {
	id, err := idFromArtifactPath(r.URL.Path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	name, filename, contentType, data, err := s.artifactData(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if filename == "" {
		filename = name
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFilename(filename)+`"`)
	w.Write(data)
}

func (s *appServer) deleteArtifact(w http.ResponseWriter, r *http.Request) {
	id, err := idFromArtifactPath(r.URL.Path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.db.Exec(`DELETE FROM artifacts WHERE id = ?`, id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *appServer) encryptArtifact(w http.ResponseWriter, r *http.Request) {
	name, filename, _, data, ok := s.readMultipartAsset(w, r)
	if !ok {
		return
	}
	pin := r.FormValue("pin")
	if err := validatePin(pin); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if name == "" {
		name = filename
	}
	locked, bundle, err := encryptWithPIN(data, filename, pin)
	if err != nil {
		http.Error(w, "encrypt failed", http.StatusInternalServerError)
		return
	}
	lockID, err := s.insertArtifact(name+" lock", outputName(filename, ".lock"), "application/octet-stream", locked)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	bundleID, err := s.insertArtifact(name+" bundle", outputName(filename, ".bundle"), "application/octet-stream", bundle)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"lock_id": lockID, "bundle_id": bundleID})
}

func (s *appServer) decryptArtifact(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AssetIDs []int64 `json:"asset_ids"`
		PIN      string  `json:"pin"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	plain, name, ok := s.tryUnlock(w, r, req.AssetIDs, req.PIN)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"name": name, "data": base64.StdEncoding.EncodeToString(plain)})
}

func (s *appServer) relockArtifact(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AssetIDs []int64 `json:"asset_ids"`
		PIN      string  `json:"pin"`
		CSV      string  `json:"csv"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	_, name, ok := s.tryUnlock(w, r, req.AssetIDs, req.PIN)
	if !ok {
		return
	}
	if len(req.AssetIDs) != 2 {
		http.Error(w, "choose exactly two registry assets", http.StatusBadRequest)
		return
	}
	_, _, _, left, err := s.artifactData(req.AssetIDs[0])
	if err != nil {
		http.Error(w, "asset not found", http.StatusNotFound)
		return
	}
	_, _, _, right, err := s.artifactData(req.AssetIDs[1])
	if err != nil {
		http.Error(w, "asset not found", http.StatusNotFound)
		return
	}
	lockID, lockData, bundleBytes := req.AssetIDs[0], left, right
	if bytes.HasPrefix(right, lockMagic) {
		lockID, lockData, bundleBytes = req.AssetIDs[1], right, left
	}
	lockBytes, err := relockWithLockAndBundle([]byte(req.CSV), name, req.PIN, lockData, bundleBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	now := s.now().Unix()
	if _, err := s.db.Exec(`UPDATE artifacts SET data = ?, updated_at = ? WHERE id = ?`, lockBytes, now, lockID); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"id": lockID})
}

func (s *appServer) tryUnlock(w http.ResponseWriter, r *http.Request, ids []int64, pin string) ([]byte, string, bool) {
	ip := clientIP(r)
	allowed, err := s.checkFailureLimit("unlock_failures", ip)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return nil, "", false
	}
	if !allowed {
		http.Error(w, "too many unlock attempts", http.StatusForbidden)
		return nil, "", false
	}
	if len(ids) != 2 {
		http.Error(w, "choose exactly two registry assets", http.StatusBadRequest)
		return nil, "", false
	}
	if err := validatePin(pin); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, "", false
	}
	_, _, _, left, err := s.artifactData(ids[0])
	if err != nil {
		http.Error(w, "asset not found", http.StatusNotFound)
		return nil, "", false
	}
	_, _, _, right, err := s.artifactData(ids[1])
	if err != nil {
		http.Error(w, "asset not found", http.StatusNotFound)
		return nil, "", false
	}
	plain, name, err := unlockPair(left, right, pin)
	if err == nil {
		return plain, name, true
	}
	banned, recErr := s.recordFailure("unlock_failures", ip)
	if recErr != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return nil, "", false
	}
	if banned {
		http.Error(w, "too many unlock attempts", http.StatusForbidden)
		return nil, "", false
	}
	http.Error(w, "unlock failed", http.StatusUnauthorized)
	return nil, "", false
}

func (s *appServer) readMultipartAsset(w http.ResponseWriter, r *http.Request) (string, string, string, []byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		http.Error(w, "upload is too large or invalid", http.StatusBadRequest)
		return "", "", "", nil, false
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return "", "", "", nil, false
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "could not read upload", http.StatusBadRequest)
		return "", "", "", nil, false
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = header.Filename
	}
	if name == "" {
		name = "artifact"
	}
	return name, safeFilename(header.Filename), contentType(header, data), data, true
}

func (s *appServer) insertArtifact(name, filename, contentType string, data []byte) (int64, error) {
	now := s.now().Unix()
	result, err := s.db.Exec(`INSERT INTO artifacts (name, filename, content_type, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, name, safeFilename(filename), contentType, data, now, now)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *appServer) artifactData(id int64) (string, string, string, []byte, error) {
	var name, filename, contentType string
	var data []byte
	err := s.db.QueryRow(`SELECT name, filename, content_type, data FROM artifacts WHERE id = ?`, id).Scan(&name, &filename, &contentType, &data)
	return name, filename, contentType, data, err
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

func idFromArtifactPath(path string) (int64, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 4 {
		return 0, errors.New("bad path")
	}
	return strconv.ParseInt(parts[3], 10, 64)
}

func contentType(header *multipart.FileHeader, data []byte) string {
	if header.Header.Get("Content-Type") != "" {
		return header.Header.Get("Content-Type")
	}
	return http.DetectContentType(data)
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
        <button class="tab active" data-admin-tab="registry" type="button">Registry</button>
        <button class="tab" data-admin-tab="encrypt" type="button">Encrypt</button>
        <button class="tab" data-admin-tab="unlock" type="button">Unlock</button>
      </nav>
      <a class="nav-cta" href="/logout">Logout</a>
    </div>
  </header>
  <main class="app-shell site-main admin-main">
    <section class="screen active" id="admin-registry">
      <div class="page-head"><h2>Artifact Registry</h2><p>Upload files under operational names. The registry does not classify locks or bundles.</p></div>
      <form class="panel form-panel" id="uploadForm">
        <div class="field"><label for="uploadName">Name</label><input class="input" id="uploadName" name="name" placeholder="Elephant"></div>
        <div class="field"><label for="uploadFile">Artifact</label><input class="input" id="uploadFile" name="file" type="file" required></div>
        <button class="primary" type="submit">Upload artifact</button>
        <div class="status" id="uploadStatus"></div>
      </form>
      <div class="artifact-list" id="artifactList"></div>
    </section>
    <section class="screen" id="admin-encrypt">
      <div class="page-head"><h2>Encrypt Into Registry</h2><p>Create a lock and bundle from an uploaded source file, then store both as named artifacts.</p></div>
      <form class="panel form-panel" id="adminEncryptForm">
        <div class="field"><label for="encryptName">Registry name</label><input class="input" id="encryptName" name="name" placeholder="Project asset"></div>
        <div class="field"><label for="encryptFile">Source file</label><input class="input" id="encryptFile" name="file" type="file" required></div>
        <div class="field"><label for="encryptPin">PIN</label><input class="input" id="encryptPin" name="pin" inputmode="numeric" pattern="[0-9]*" autocomplete="off" required></div>
        <button class="primary" type="submit">Encrypt and store</button>
        <div class="status" id="adminEncryptStatus"></div>
      </form>
    </section>
    <section class="screen" id="admin-unlock">
      <div class="page-head"><h2>Unlock Assets</h2><p>Pick any two artifacts and enter the PIN. Successful CSV unlocks open in spreadsheet mode and can be relocked into the same registry lock.</p></div>
      <form class="panel form-panel" id="unlockForm">
        <div class="edit-credential-grid">
          <div class="field"><label for="assetA">First artifact</label><select class="input" id="assetA" required></select></div>
          <div class="field"><label for="assetB">Second artifact</label><select class="input" id="assetB" required></select></div>
        </div>
        <div class="field"><label for="unlockPin">PIN</label><input class="input" id="unlockPin" inputmode="numeric" pattern="[0-9]*" autocomplete="off" required></div>
        <div class="actions"><button class="primary" type="submit">Unlock</button><button class="secondary" id="decryptDownload" type="button">Decrypt download</button></div>
        <div class="status" id="unlockStatus"></div>
      </form>
      <div class="text-workspace" id="adminWorkspace" hidden>
        <div class="editor-toolbar"><div><h3 id="adminEditorTitle">Spreadsheet editor</h3><div class="hint" id="adminEditorMeta"></div></div><button class="primary" id="adminRelock" type="button">Relock into registry</button></div>
        <div class="sheet-actions"><button class="secondary" id="adminAddRow" type="button">Add row</button><button class="secondary" id="adminAddColumn" type="button">Add column</button></div>
        <div class="spreadsheet-scroll"><table class="spreadsheet" id="adminGrid"></table></div>
        <div class="status" id="relockStatus"></div>
      </div>
    </section>
  </main>
  <script src="/admin.js" defer></script>
</body>
</html>`))
