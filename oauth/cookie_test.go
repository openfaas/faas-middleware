package oauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCookieProtection(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	codec := testCodec(t, cfg)
	token := Token{IDToken: "id-token", AccessToken: "access-token"}
	first, err := codec.Encode(cfg.CookieName, token, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Independently verify that the cookie is a signed JWT with standard claims.
	claims := cookieClaims{}
	parsed, err := jwt.ParseWithClaims(first, &claims, func(*jwt.Token) (any, error) { return cfg.CookieSecret, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(cfg.BaseURL.String()), jwt.WithAudience(cfg.BaseURL.String()), jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid {
		t.Fatalf("cookie is not a valid signed JWT: %v", err)
	}
	if claims.IssuedAt == nil || claims.CookieName != cfg.CookieName {
		t.Fatal("cookie missing required claims")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(first, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["encrypted_value"]; ok {
		t.Fatal("cookie still contains an encrypted payload")
	}
	var exposed Token
	if err := json.Unmarshal(fields["value"], &exposed); err != nil {
		t.Fatal(err)
	}
	if exposed != token {
		t.Fatal("JWT must contain the readable OAuth token response")
	}
	// A separately constructed codec simulates another replica or a restart.
	var decoded Token
	if err := testCodec(t, cfg).Decode(cfg.CookieName, first, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != token {
		t.Fatal("token response changed")
	}
	otherKey := cfg
	otherKey.CookieSecret = []byte(strings.Repeat("k", 32))
	if err := testCodec(t, otherKey).Decode(cfg.CookieName, first, &decoded); err == nil {
		t.Fatal("accepted a different key")
	}
	if err := codec.Decode(cfg.LoginCookie, first, &decoded); err == nil {
		t.Fatal("accepted a different cookie name")
	}
	otherScope := cfg
	base := *cfg.BaseURL
	base.Path = "/function/other"
	otherScope.BaseURL = &base
	if err := testCodec(t, otherScope).Decode(cfg.CookieName, first, &decoded); err == nil {
		t.Fatal("accepted a different function scope")
	}
	// Modify the JWT payload without re-signing it.
	parts := strings.Split(first, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString(append(payload, ' '))
	if err := codec.Decode(cfg.CookieName, strings.Join(parts, "."), &decoded); err == nil {
		t.Fatal("accepted tampered JWT")
	}
	for _, value := range []string{"", "plaintext", "v1.old-cookie", "a.b.c", strings.Repeat("x", maxCookieValueBytes+1)} {
		if err := codec.Decode(cfg.CookieName, value, &decoded); err == nil {
			t.Fatal("accepted malformed cookie")
		}
	}
}

func signCookieClaims(t *testing.T, codec *CookieCodec, claims cookieClaims, method jwt.SigningMethod, key any) string {
	t.Helper()
	encoded, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func validCookieClaims(t *testing.T, codec *CookieCodec, name string) cookieClaims {
	t.Helper()
	value, err := codec.Encode(name, Token{AccessToken: "token"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	claims := cookieClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(value, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestCookieRejectsInvalidClaims(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	codec := testCodec(t, cfg)
	for name, change := range map[string]func(*cookieClaims){
		"wrong issuer":       func(c *cookieClaims) { c.Issuer = "https://other.example/auth" },
		"missing issuer":     func(c *cookieClaims) { c.Issuer = "" },
		"wrong audience":     func(c *cookieClaims) { c.Audience = jwt.ClaimStrings{"https://other.example/function"} },
		"missing audience":   func(c *cookieClaims) { c.Audience = nil },
		"multiple audiences": func(c *cookieClaims) { c.Audience = append(c.Audience, "https://other.example/function") },
		"expired":            func(c *cookieClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Second)) },
		"missing expiry":     func(c *cookieClaims) { c.ExpiresAt = nil },
		"missing issued at":  func(c *cookieClaims) { c.IssuedAt = nil },
		"future issued at":   func(c *cookieClaims) { c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour)) },
		"wrong cookie name":  func(c *cookieClaims) { c.CookieName = "different" },
		"missing value":      func(c *cookieClaims) { c.Value = nil },
		"null value":         func(c *cookieClaims) { c.Value = json.RawMessage(`null`) },
		"wrong value type":   func(c *cookieClaims) { c.Value = json.RawMessage(`"not a token response"`) },
	} {
		t.Run(name, func(t *testing.T) {
			claims := validCookieClaims(t, codec, cfg.CookieName)
			change(&claims)
			encoded := signCookieClaims(t, codec, claims, jwt.SigningMethodHS256, codec.signingKey)
			var token Token
			if err := codec.Decode(cfg.CookieName, encoded, &token); err == nil {
				t.Fatal("accepted invalid signed claims")
			}
		})
	}
	claims := validCookieClaims(t, codec, cfg.CookieName)
	for _, tc := range []struct {
		method jwt.SigningMethod
		key    any
	}{
		{jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType},
		{jwt.SigningMethodHS384, codec.signingKey},
	} {
		var token Token
		if err := codec.Decode(cfg.CookieName, signCookieClaims(t, codec, claims, tc.method, tc.key), &token); err == nil {
			t.Fatal("accepted disallowed signing algorithm")
		}
	}
}

func TestCookieExpiryAndSize(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	codec := testCodec(t, cfg)
	if _, err := codec.Encode(cfg.CookieName, Token{}, time.Now().Add(-time.Second)); err == nil {
		t.Fatal("issued expired cookie")
	}
	if _, err := codec.Encode(cfg.CookieName, strings.Repeat("x", maxCookieValueBytes), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("issued oversized cookie")
	}
}

func TestCookieRejectsInvalidKey(t *testing.T) {
	for _, size := range []int{0, 16, 24, 31, 33} {
		if _, err := NewCookieCodec(make([]byte, size), "https://example.com"); err == nil {
			t.Fatalf("accepted key length %d", size)
		}
	}
}
