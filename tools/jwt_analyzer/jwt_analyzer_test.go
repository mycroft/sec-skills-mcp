package jwt_analyzer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// buildHS256Token creates a minimal HS256-signed JWT for testing purposes.
func buildHS256Token(payloadMap map[string]interface{}, secret string) string {
	headerJSON, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payloadJSON, _ := json.Marshal(payloadMap)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

func TestAnalyze_EmptyToken(t *testing.T) {
	_, err := Analyze("")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestAnalyze_InvalidFormat(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"no dots", "notavalidtoken"},
		{"one dot", "header.payload"},
		{"too many parts", "a.b.c.d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Analyze(tc.token)
			if err == nil {
				t.Errorf("expected error for token %q, got nil", tc.token)
			}
		})
	}
}

func TestAnalyze_NoneAlgorithm(t *testing.T) {
	// JWT with alg=none: header={"alg":"none","typ":"JWT"}, payload={"sub":"test"}, no signature
	// eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.
	token := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0."
	result, err := Analyze(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "none") {
		t.Errorf("expected 'none' in result, got:\n%s", result)
	}
	if !strings.Contains(result, "CRITICAL") {
		t.Errorf("expected CRITICAL vulnerability for none algorithm, got:\n%s", result)
	}
}

func TestAnalyze_NoExpiration(t *testing.T) {
	token := buildHS256Token(map[string]interface{}{"sub": "user"}, "strongsecret")
	result, err := Analyze(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Expiration (exp):  NOT SET") {
		t.Errorf("expected no-expiration notice, got:\n%s", result)
	}
	if !strings.Contains(result, "WARNING: No expiration") {
		t.Errorf("expected WARNING for missing exp, got:\n%s", result)
	}
}

func TestAnalyze_WeakSecret(t *testing.T) {
	token := buildHS256Token(map[string]interface{}{"sub": "user"}, "secret")
	result, err := Analyze(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Weak signing secret") {
		t.Errorf("expected weak secret detection, got:\n%s", result)
	}
	if !strings.Contains(result, `"secret"`) {
		t.Errorf("expected detected secret to be 'secret', got:\n%s", result)
	}
}

func TestAnalyze_StrongSecret_NoWeakDetection(t *testing.T) {
	token := buildHS256Token(map[string]interface{}{"sub": "user"}, "this-is-a-very-strong-random-secret-xyz")
	result, err := Analyze(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(result, "Weak signing secret") {
		t.Errorf("should not detect weak secret for strong key, got:\n%s", result)
	}
}

func TestAnalyze_ValidToken_Structure(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	token := buildHS256Token(map[string]interface{}{
		"sub": "1234567890",
		"iss": "test-issuer",
		"exp": exp,
	}, "strongsecret")

	result, err := Analyze(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, section := range []string{"Header", "Payload", "Signature", "Vulnerability"} {
		if !strings.Contains(result, section) {
			t.Errorf("expected section %q in result, got:\n%s", section, result)
		}
	}
	if !strings.Contains(result, "Issuer (iss):") {
		t.Errorf("expected issuer in result, got:\n%s", result)
	}
}

func TestAnalyze_ExpiredToken(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	token := buildHS256Token(map[string]interface{}{
		"sub": "user",
		"exp": past,
	}, "strongsecret")

	result, err := Analyze(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "EXPIRED") {
		t.Errorf("expected EXPIRED in result, got:\n%s", result)
	}
	if !strings.Contains(result, "WARNING: Token is EXPIRED") {
		t.Errorf("expected expired vulnerability warning, got:\n%s", result)
	}
}

func TestAnalyze_NotYetValid(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	token := buildHS256Token(map[string]interface{}{
		"sub": "user",
		"nbf": future,
	}, "strongsecret")

	result, err := Analyze(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "NOT YET VALID") {
		t.Errorf("expected NOT YET VALID notice, got:\n%s", result)
	}
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0m"},
		{30 * time.Minute, "30m"},
		{90 * time.Minute, "1h 30m"},
		{25*time.Hour + 30*time.Minute, "1d 1h 30m"},
	}
	for _, tc := range cases {
		got := formatDuration(tc.d)
		if got != tc.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestDecodeSegment_Padding(t *testing.T) {
	cases := []struct {
		input string
		valid bool
	}{
		{"eyJhbGciOiJub25lIn0", true},
		{"eyJhbGciOiJIUzI1NiJ9", true},
	}
	for _, tc := range cases {
		_, err := decodeSegment(tc.input)
		if tc.valid && err != nil {
			t.Errorf("decodeSegment(%q) unexpected error: %v", tc.input, err)
		}
	}
}
