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
