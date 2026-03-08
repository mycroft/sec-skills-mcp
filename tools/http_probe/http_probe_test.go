package http_probe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbe_EmptyURL(t *testing.T) {
	_, err := Probe("", ProbeOptions{})
	if err == nil {
		t.Fatal("expected error for empty URL, got nil")
	}
}

func TestProbe_InvalidScheme(t *testing.T) {
	cases := []string{
		"ftp://example.com",
		"file:///etc/passwd",
		"javascript:alert(1)",
	}
	for _, tc := range cases {
		_, err := Probe(tc, ProbeOptions{})
		if err == nil {
			t.Errorf("expected error for URL %q, got nil", tc)
		}
	}
}

func TestProbe_InvalidURL(t *testing.T) {
	cases := []string{
		"not-a-url",
		"http://",
		"://missing-scheme",
	}
	for _, tc := range cases {
		_, err := Probe(tc, ProbeOptions{})
		if err == nil {
			t.Errorf("expected error for URL %q, got nil", tc)
		}
	}
}

func TestProbe_BasicRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("X-Powered-By", "Go")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result, err := Probe(srv.URL, ProbeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result, "200 OK") {
		t.Errorf("expected status 200 OK in result, got:\n%s", result)
	}
	if !strings.Contains(result, "TestServer/1.0") {
		t.Errorf("expected Server header in result, got:\n%s", result)
	}
	if !strings.Contains(result, "Server: TestServer/1.0") {
		t.Errorf("expected technology detection for Server header, got:\n%s", result)
	}
}

func TestProbe_TechDetection_XPoweredBy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.1")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result, err := Probe(srv.URL, ProbeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "X-Powered-By: PHP/8.1") {
		t.Errorf("expected X-Powered-By detection, got:\n%s", result)
	}
}

func TestProbe_TechDetection_Cloudflare(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "abc123-LAX")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result, err := Probe(srv.URL, ProbeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Cloudflare") {
		t.Errorf("expected Cloudflare detection, got:\n%s", result)
	}
}

func TestProbe_CookieDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "PHPSESSID",
			Value:    "abc123",
			HttpOnly: true,
			Secure:   false,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result, err := Probe(srv.URL, ProbeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "PHPSESSID") {
		t.Errorf("expected PHPSESSID cookie in result, got:\n%s", result)
	}
	if !strings.Contains(result, "PHP") {
		t.Errorf("expected PHP technology detection via cookie, got:\n%s", result)
	}
	if !strings.Contains(result, "HttpOnly") {
		t.Errorf("expected HttpOnly attribute in cookie output, got:\n%s", result)
	}
}

func TestProbe_Redirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/new", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	result, err := Probe(srv.URL, ProbeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "301") {
		t.Errorf("expected 301 status in result, got:\n%s", result)
	}
	if !strings.Contains(result, "Redirect:") {
		t.Errorf("expected Redirect line in result, got:\n%s", result)
	}
}

func TestProbe_CheckPaths(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User-agent: *\nDisallow: /admin\n")) //nolint:errcheck
	})
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ref: refs/heads/main\n")) //nolint:errcheck
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	result, err := Probe(srv.URL, ProbeOptions{CheckPaths: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Common Path Probe:") {
		t.Errorf("expected 'Common Path Probe:' section, got:\n%s", result)
	}
	if !strings.Contains(result, "/robots.txt") {
		t.Errorf("expected /robots.txt probe, got:\n%s", result)
	}
	if !strings.Contains(result, "/.git/HEAD") {
		t.Errorf("expected /.git/HEAD probe, got:\n%s", result)
	}
}

func TestProbe_NoPaths_WhenNotRequested(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result, err := Probe(srv.URL, ProbeOptions{CheckPaths: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(result, "Common Path Probe:") {
		t.Errorf("did not expect path probe section when CheckPaths=false, got:\n%s", result)
	}
}
