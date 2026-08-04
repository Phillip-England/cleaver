package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminCSVUploadReturnsCompleteRecoveryKit(t *testing.T) {
	s := newTestAppServer(t)
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	_ = writer.WriteField("name", "Quarterly report")
	_ = writer.WriteField("pin", "2468")
	part, err := writer.CreateFormFile("file", "report.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("name,total\nAda,42\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/encrypt", &requestBody)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	s.encryptArtifact(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		LockData       string `json:"lock_data"`
		LockName       string `json:"lock_name"`
		KeyName        string `json:"key_name"`
		KeyDownloadURL string `json:"key_download_url"`
		PublicURL      string `json:"public_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.LockName != "report.lock" || result.KeyName != "report.key" {
		t.Fatalf("unexpected recovery filenames: lock=%q key=%q", result.LockName, result.KeyName)
	}
	if result.KeyDownloadURL == "" || result.PublicURL == "" {
		t.Fatalf("missing recovery URLs: key=%q public=%q", result.KeyDownloadURL, result.PublicURL)
	}

	keyReq := httptest.NewRequest(http.MethodGet, result.KeyDownloadURL, nil)
	keyRec := httptest.NewRecorder()
	s.downloadKey(keyRec, keyReq)
	if keyRec.Code != http.StatusOK || keyRec.Body.Len() == 0 {
		t.Fatalf("key download status %d: %s", keyRec.Code, keyRec.Body.String())
	}
	locked, err := base64.StdEncoding.DecodeString(result.LockData)
	if err != nil {
		t.Fatal(err)
	}
	plain, name, err := unlockPair(locked, keyRec.Body.Bytes(), "2468")
	if err != nil {
		t.Fatal(err)
	}
	if name != "report.csv" || string(plain) != "name,total\nAda,42\n" {
		t.Fatalf("downloaded recovery kit did not unlock original CSV: name=%q data=%q", name, plain)
	}
}

func TestStaticHandlerServesIndex(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`<script src="/app.js" defer></script>`)) {
		t.Fatal("index did not reference the client app")
	}
}

func TestStaticHandlerServesClientAssets(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/app.js", "/styles.css"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status %d", path, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Fatalf("%s was empty", path)
		}
	}
}

func TestStaticHandlerFallsBackToIndexForBrowserRoutes(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/encrypt", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`<title>Cleaver</title>`)) {
		t.Fatal("fallback did not serve index")
	}
}

func TestStaticHandlerServesIntroByDefault(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.Bytes()
	if !bytes.Contains(body, []byte(`What Cleaver Does`)) {
		t.Fatal("index did not include the introduction page")
	}
	if !bytes.Contains(body, []byte(`data-tab="encrypt"`)) || !bytes.Contains(body, []byte(`data-tab="decrypt"`)) {
		t.Fatal("index did not include encrypt and decrypt pages")
	}
	if !bytes.Contains(body, []byte(`data-tab="edit"`)) || !bytes.Contains(body, []byte(`id="spreadsheetGrid"`)) {
		t.Fatal("index did not include the CSV spreadsheet editor")
	}
	if !bytes.Contains(body, []byte(`id="addSheetRow"`)) || !bytes.Contains(body, []byte(`id="addSheetColumn"`)) {
		t.Fatal("index did not include spreadsheet row and column controls")
	}
}

func TestCSVEditorUsesSpreadsheetWorkflow(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body := rec.Body.Bytes()
	for _, text := range [][]byte{
		[]byte(`requireCSVName`),
		[]byte(`parseCSV`),
		[]byte(`normalizeCSVRows`),
		[]byte(`renderSpreadsheet`),
		[]byte(`handleSpreadsheetKeydown`),
		[]byte(`serializeCSV`),
		[]byte(`Protected by the same PIN and key bundle`),
	} {
		if !bytes.Contains(body, text) {
			t.Fatalf("CSV spreadsheet editor logic did not include %q", text)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`Unlock spreadsheet`)) {
		t.Fatal("CSV editor did not include an unlock spreadsheet control")
	}
}

func TestUIUsesSingleKeyBundleWorkflow(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body := rec.Body.Bytes()
	for _, text := range [][]byte{
		[]byte(`one portable key bundle`),
		[]byte(`Key bundle`),
		[]byte(`Export new lock file`),
	} {
		if !bytes.Contains(body, text) {
			t.Fatalf("index did not include %q", text)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body = rec.Body.Bytes()
	for _, text := range [][]byte{
		[]byte(`CLEAVER-BUNDLE1`),
		[]byte(`shard_ids`),
		[]byte(`encodeKeyBundle`),
	} {
		if !bytes.Contains(body, text) {
			t.Fatalf("client did not include %q", text)
		}
	}
}

func TestLockWorkflowsAcceptLockAndBundleTogether(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body := rec.Body.Bytes()
	for _, id := range []string{"decryptAsset", "editAsset"} {
		want := []byte(`id="` + id + `" name="asset" type="file" accept=".lock,.bundle,.key" multiple`)
		if !bytes.Contains(body, want) {
			t.Fatalf("combined lock and bundle picker missing for %s", id)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body = rec.Body.Bytes()
	for _, text := range [][]byte{[]byte(`selectedFiles.find`), []byte(`bundle|key`), []byte(`setInputFiles(bundleInput`)} {
		if !bytes.Contains(body, text) {
			t.Fatalf("combined picker logic did not include %q", text)
		}
	}
}

func TestStaticHandlerRejectsMutatingMethods(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/encrypt", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestBrowserURLUsesLocalhostForWildcardListeners(t *testing.T) {
	tests := map[string]string{
		"0.0.0.0:5544": "http://localhost:5544",
		":5544":        "http://localhost:5544",
		"[::]:5544":    "http://localhost:5544",
		"127.0.0.1:80": "http://127.0.0.1:80",
	}

	for addr, want := range tests {
		if got := browserURL(addr); got != want {
			t.Errorf("browserURL(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestInitCreatesConfigAndSQLite(t *testing.T) {
	withTempWorkingDir(t, func(dir string) {
		var out bytes.Buffer
		if err := initApp(&out); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "config/.env")); err != nil {
			t.Fatalf("config was not created: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "data/main.sqlite")); err != nil {
			t.Fatalf("sqlite database was not created: %v", err)
		}
		if !strings.Contains(out.String(), "initialized config/.env") {
			t.Fatalf("unexpected init output: %s", out.String())
		}
	})
}

func TestAdminRoutesRequireSession(t *testing.T) {
	server := newTestAppServer(t)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Fatalf("redirect = %q, want /login", got)
	}
}

func TestLoginFailuresBanIPAfterFiveAttempts(t *testing.T) {
	server := newTestAppServer(t)

	for attempt := 1; attempt <= 5; attempt++ {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=admin&password=wrong"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.7:12345"
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)

		if attempt < 5 && rec.Code != http.StatusOK {
			t.Fatalf("attempt %d status %d", attempt, rec.Code)
		}
		if attempt == 5 && rec.Code != http.StatusForbidden {
			t.Fatalf("attempt %d status %d, want 403", attempt, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=admin&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.7:12345"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("banned correct login status %d, want 403", rec.Code)
	}
}

func TestServerLockAndBundleRoundTrip(t *testing.T) {
	locked, bundle, err := encryptWithPIN([]byte("a,b\n1,2\n"), "sample.csv", "1234")
	if err != nil {
		t.Fatal(err)
	}
	plain, name, err := unlockPair(bundle, locked, "1234")
	if err != nil {
		t.Fatal(err)
	}
	if name != "sample.csv" {
		t.Fatalf("name = %q", name)
	}
	if string(plain) != "a,b\n1,2\n" {
		t.Fatalf("plain = %q", string(plain))
	}
	if _, _, err := unlockPair(bundle, locked, "9999"); err == nil {
		t.Fatal("wrong PIN decrypted successfully")
	}
}

func newTestAppServer(t *testing.T) *appServer {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "main.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	public, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}
	return &appServer{
		db: db,
		cfg: config{
			AdminUsername: "admin",
			AdminPassword: "secret",
			SessionSecret: []byte("test-secret"),
		},
		public: public,
		now:    func() time.Time { return time.Unix(1800000000, 0) },
	}
}

func withTempWorkingDir(t *testing.T, fn func(string)) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Fatal(err)
		}
	})
	fn(dir)
}
