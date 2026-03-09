package jwt_analyzer

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"
)

// weakSecrets is a list of commonly used weak JWT secrets to test against.
var weakSecrets = []string{
	"secret",
	"password",
	"123456",
	"key",
	"jwt",
	"token",
	"supersecret",
	"changeme",
	"default",
	"admin",
	"test",
	"qwerty",
	"letmein",
	"pass",
	"1234",
	"abc123",
}

// header represents the decoded JWT header fields.
type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
	raw       map[string]interface{}
}

// payload represents the decoded JWT payload claims.
type payload struct {
	Issuer     string      `json:"iss,omitempty"`
	Subject    string      `json:"sub,omitempty"`
	Audience   interface{} `json:"aud,omitempty"`
	Expiration *int64      `json:"exp,omitempty"`
	NotBefore  *int64      `json:"nbf,omitempty"`
	IssuedAt   *int64      `json:"iat,omitempty"`
	JWTID      string      `json:"jti,omitempty"`
	raw        map[string]interface{}
}

// decodeSegment decodes a base64url-encoded JWT segment (no padding required).
func decodeSegment(seg string) ([]byte, error) {
	// Add padding if needed
	switch len(seg) % 4 {
	case 2:
		seg += "=="
	case 3:
		seg += "="
	}
	return base64.URLEncoding.DecodeString(seg)
}

// Analyze decodes and analyzes a JWT token, checking for vulnerabilities.
func Analyze(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("token must not be empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts separated by '.', got %d", len(parts))
	}

	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT header: %w", err)
	}

	payloadBytes, err := decodeSegment(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var h header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return "", fmt.Errorf("failed to parse JWT header: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &h.raw); err != nil {
		return "", fmt.Errorf("failed to parse JWT header: %w", err)
	}

	var p payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return "", fmt.Errorf("failed to parse JWT payload: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &p.raw); err != nil {
		return "", fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("=== JWT Analysis ===\n\n")

	// Header section
	sb.WriteString("--- Header ---\n")
	fmt.Fprintf(&sb, "Algorithm: %s\n", h.Algorithm)
	fmt.Fprintf(&sb, "Type:      %s\n", h.Type)
	if h.KeyID != "" {
		fmt.Fprintf(&sb, "Key ID:    %s\n", h.KeyID)
	}
	// Print any extra header fields
	for k, v := range h.raw {
		if k == "alg" || k == "typ" || k == "kid" {
			continue
		}
		fmt.Fprintf(&sb, "%-10s %v\n", k+":", v)
	}

	// Payload section
	sb.WriteString("\n--- Payload / Claims ---\n")
	if p.Issuer != "" {
		fmt.Fprintf(&sb, "Issuer (iss):      %s\n", p.Issuer)
	}
	if p.Subject != "" {
		fmt.Fprintf(&sb, "Subject (sub):     %s\n", p.Subject)
	}
	if p.Audience != nil {
		switch aud := p.Audience.(type) {
		case string:
			fmt.Fprintf(&sb, "Audience (aud):    %s\n", aud)
		case []interface{}:
			audStrs := make([]string, 0, len(aud))
			for _, a := range aud {
				audStrs = append(audStrs, fmt.Sprintf("%v", a))
			}
			fmt.Fprintf(&sb, "Audience (aud):    %s\n", strings.Join(audStrs, ", "))
		}
	}
	if p.JWTID != "" {
		fmt.Fprintf(&sb, "JWT ID (jti):      %s\n", p.JWTID)
	}

	now := time.Now()

	if p.IssuedAt != nil {
		iat := time.Unix(*p.IssuedAt, 0)
		fmt.Fprintf(&sb, "Issued At (iat):   %s\n", iat.UTC().Format(time.RFC3339))
	}
	if p.NotBefore != nil {
		nbf := time.Unix(*p.NotBefore, 0)
		if now.Before(nbf) {
			fmt.Fprintf(&sb, "Not Before (nbf):  %s  [NOT YET VALID]\n", nbf.UTC().Format(time.RFC3339))
		} else {
			fmt.Fprintf(&sb, "Not Before (nbf):  %s\n", nbf.UTC().Format(time.RFC3339))
		}
	}
	if p.Expiration != nil {
		exp := time.Unix(*p.Expiration, 0)
		if now.After(exp) {
			fmt.Fprintf(&sb, "Expiration (exp):  %s  [EXPIRED]\n", exp.UTC().Format(time.RFC3339))
		} else {
			remaining := time.Until(exp)
			fmt.Fprintf(&sb, "Expiration (exp):  %s  (expires in %s)\n", exp.UTC().Format(time.RFC3339), formatDuration(remaining))
		}
	} else {
		fmt.Fprintf(&sb, "Expiration (exp):  NOT SET\n")
	}

	// Extra claims
	knownClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true,
		"exp": true, "nbf": true, "iat": true, "jti": true,
	}
	var extraClaims []string
	for k := range p.raw {
		if !knownClaims[k] {
			extraClaims = append(extraClaims, k)
		}
	}
	if len(extraClaims) > 0 {
		sb.WriteString("\nCustom Claims:\n")
		for _, k := range extraClaims {
			fmt.Fprintf(&sb, "  %-18s %v\n", k+":", p.raw[k])
		}
	}

	// Signature section
	sb.WriteString("\n--- Signature ---\n")
	sigBytes, err := decodeSegment(parts[2])
	if err != nil {
		sb.WriteString("Signature: (could not decode)\n")
	} else if len(sigBytes) == 0 {
		sb.WriteString("Signature: EMPTY (unsigned token)\n")
	} else {
		fmt.Fprintf(&sb, "Signature: %d bytes (base64url encoded)\n", len(sigBytes))
	}

	// Vulnerability checks
	sb.WriteString("\n--- Vulnerability Analysis ---\n")
	var vulns []string

	// Check: none algorithm
	alg := strings.ToLower(h.Algorithm)
	if alg == "none" || alg == "" {
		vulns = append(vulns, "CRITICAL: Algorithm is 'none' — token is unsigned and trivially forgeable")
	}

	// Check: no expiration
	if p.Expiration == nil {
		vulns = append(vulns, "WARNING: No expiration (exp) claim — token never expires and cannot be invalidated by time")
	} else if now.After(time.Unix(*p.Expiration, 0)) {
		vulns = append(vulns, "WARNING: Token is EXPIRED")
	}

	// Check: not-before in the future
	if p.NotBefore != nil && now.Before(time.Unix(*p.NotBefore, 0)) {
		vulns = append(vulns, "INFO: Token is not yet valid (nbf is in the future)")
	}

	// Check: weak secrets for HMAC algorithms
	weakSecret := checkWeakSecret(parts[0]+"."+parts[1], parts[2], h.Algorithm)
	if weakSecret != "" {
		vulns = append(vulns, fmt.Sprintf("CRITICAL: Weak signing secret detected: %q — token can be forged", weakSecret))
	}

	// Check: algorithm confusion (RS/ES algorithm with short key)
	if strings.HasPrefix(alg, "hs") && len(parts[2]) < 20 {
		vulns = append(vulns, "WARNING: HMAC signature appears very short — possible weak key")
	}

	if len(vulns) == 0 {
		sb.WriteString("No obvious vulnerabilities detected.\n")
	} else {
		for _, v := range vulns {
			fmt.Fprintf(&sb, "  [!] %s\n", v)
		}
	}

	return sb.String(), nil
}

// checkWeakSecret tries to verify the JWT signature against a list of common
// weak secrets. Returns the matching secret if found, or "" if none matched.
func checkWeakSecret(signingInput, signatureB64, algorithm string) string {
	alg := strings.ToUpper(algorithm)

	var newHashFunc func() hash.Hash
	switch alg {
	case "HS256":
		newHashFunc = sha256.New
	case "HS384":
		newHashFunc = sha512.New384
	case "HS512":
		newHashFunc = sha512.New
	default:
		// Only HMAC-based algorithms can be checked this way
		return ""
	}

	sigBytes, err := decodeSegment(signatureB64)
	if err != nil {
		return ""
	}

	for _, secret := range weakSecrets {
		mac := hmac.New(newHashFunc, []byte(secret))
		mac.Write([]byte(signingInput))
		expected := mac.Sum(nil)
		if hmac.Equal(expected, sigBytes) {
			return secret
		}
	}
	return ""
}

// formatDuration formats a duration as a human-readable string.
func formatDuration(d time.Duration) string {
	if d < 0 {
		return "expired"
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
