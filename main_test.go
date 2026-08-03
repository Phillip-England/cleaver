package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
	if !bytes.Contains(body, []byte(`data-tab="edit"`)) || !bytes.Contains(body, []byte(`id="textEditor"`)) {
		t.Fatal("index did not include the lock file editor")
	}
	if !bytes.Contains(body, []byte(`id="editorPageNavigation"`)) || !bytes.Contains(body, []byte(`id="editorPageTitle"`)) {
		t.Fatal("index did not include the paged Markdown editor")
	}
	if !bytes.Contains(body, []byte(`data-tab="render"`)) || !bytes.Contains(body, []byte(`id="renderForm"`)) {
		t.Fatal("index did not include the Markdown lock renderer")
	}
	if !bytes.Contains(body, []byte(`data-tab="alphabetize"`)) || !bytes.Contains(body, []byte(`id="alphabetizeForm"`)) {
		t.Fatal("index did not include the Markdown section alphabetizer")
	}
	if !bytes.Contains(body, []byte(`data-tab="markdown-docs"`)) || !bytes.Contains(body, []byte(`id="markdown-docs"`)) {
		t.Fatal("index did not include the Markdown formatting guide")
	}
}

func TestMarkdownAlphabetizerUsesExistingCredentials(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body := rec.Body.Bytes()
	for _, text := range [][]byte{
		[]byte(`alphabetizeMarkdownSections`),
		[]byte(`alphabetizeMarkdownPage`),
		[]byte(`Only single # headings are allowed`),
		[]byte(`sensitivity: "base"`),
		[]byte(`shardIds: decoded.header.shard_ids`),
		[]byte(`alphabetizedLockName(originalName)`),
	} {
		if !bytes.Contains(body, text) {
			t.Fatalf("Markdown alphabetizer logic did not include %q", text)
		}
	}
}

func TestMarkdownEditorUsesTitledPages(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body := rec.Body.Bytes()
	for _, text := range [][]byte{
		[]byte(`renderEditorPages`),
		[]byte(`activateEditorPage`),
		[]byte(`addEditorPage`),
		[]byte(`saveActiveEditorPage`),
		[]byte(`serializeMarkdownPages`),
		[]byte(`reserved for page markers`),
	} {
		if !bytes.Contains(body, text) {
			t.Fatalf("paged Markdown editor logic did not include %q", text)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`id="addEditorPage"`)) {
		t.Fatal("paged Markdown editor did not include an add-page control")
	}
}

func TestMarkdownRendererIsRestrictedToLockFiles(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body := rec.Body.Bytes()
	for _, text := range [][]byte{
		[]byte(`accept=".lock"`),
		[]byte(`Render Markdown Lock File`),
		[]byte(`id="renderOutput"`),
	} {
		if !bytes.Contains(body, text) {
			t.Fatalf("Markdown renderer UI did not include %q", text)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body = rec.Body.Bytes()
	for _, text := range [][]byte{
		[]byte(`requireMarkdownName`),
		[]byte(`fetch("/api/render"`),
		[]byte(`html: await response.text()`),
		[]byte(`buildRenderNavigation`),
		[]byte(`querySelectorAll("h1")`),
		[]byte(`makeRenderedListItemsCopyable`),
		[]byte(`querySelectorAll("li")`),
		[]byte(`copyTextToClipboard`),
		[]byte(`parseMarkdownPages`),
		[]byte(`renderMarkdownPages`),
		[]byte(`renderPageNavigationLinks`),
	} {
		if !bytes.Contains(body, text) {
			t.Fatalf("Markdown renderer logic did not include %q", text)
		}
	}
}

func TestRenderMarkdown(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/render", bytes.NewBufferString("# Hello\n\n- one\n- two\n"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	for _, want := range [][]byte{[]byte("<h1>Hello</h1>"), []byte("<li>one</li>")} {
		if !bytes.Contains(rec.Body.Bytes(), want) {
			t.Fatalf("rendered HTML did not include %q", want)
		}
	}
}

func TestRenderMarkdownDoesNotRenderRawHTML(t *testing.T) {
	handler, err := staticHandler()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/render", bytes.NewBufferString("<script>alert(1)</script>"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if bytes.Contains(rec.Body.Bytes(), []byte("<script>")) {
		t.Fatal("raw HTML was rendered")
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
		[]byte(`one key bundle`),
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
	for _, id := range []string{"decryptAsset", "editAsset", "renderAsset", "alphabetizeAsset"} {
		want := []byte(`id="` + id + `" name="asset" type="file" accept=".lock,.bundle" multiple`)
		if !bytes.Contains(body, want) {
			t.Fatalf("combined lock and bundle picker missing for %s", id)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body = rec.Body.Bytes()
	for _, text := range [][]byte{[]byte(`selectedFiles.find`), []byte(`endsWith(".bundle")`), []byte(`setInputFiles(bundleInput`)} {
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
