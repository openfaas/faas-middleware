package oauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSessionCookieProtection(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	codec := testCodec(t, cfg)
	verified := true
	session := sessionClaims{
		Type:            sessionTokenType,
		FederatedIssuer: "https://issuer.example",
		FederatedEmail:  "alice@example.com",
		EmailVerified:   &verified,
		FederatedName:   "Alice",
	}
	session.Subject = "fed:alice"
	encoded := testSessionToken(t, cfg, session, time.Now().Add(time.Hour))

	claims := sessionClaims{}
	parsed, err := jwt.ParseWithClaims(encoded, &claims, func(*jwt.Token) (any, error) { return cfg.CookieSecret, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(cfg.BaseURL.String()), jwt.WithAudience(cfg.BaseURL.String()), jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid {
		t.Fatalf("cookie is not a valid signed JWT: %v", err)
	}
	if claims.IssuedAt == nil || claims.Type != sessionTokenType || claims.Subject != "fed:alice" || claims.FederatedEmail != "alice@example.com" {
		t.Fatalf("cookie missing required top-level claims: %+v", claims)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(encoded, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	for _, obsolete := range []string{"value", "cookie_name", "encrypted_value"} {
		if _, ok := fields[obsolete]; ok {
			t.Fatalf("session JWT contains obsolete %q wrapper claim", obsolete)
		}
	}

	var decoded sessionClaims
	if err := codec.decode(encoded, &decoded, sessionTokenType); err != nil {
		t.Fatal(err)
	}
	if decoded.Subject != session.Subject || decoded.FederatedIssuer != session.FederatedIssuer || decoded.FederatedEmail != session.FederatedEmail {
		t.Fatal("session identity changed")
	}

	otherKey := cfg
	otherKey.CookieSecret = []byte(strings.Repeat("k", 32))
	if err := testCodec(t, otherKey).decode(encoded, &decoded, sessionTokenType); err == nil {
		t.Fatal("accepted a different key")
	}
	otherScope := cfg
	base := *cfg.BaseURL
	base.Path = "/function/other"
	otherScope.BaseURL = &base
	if err := testCodec(t, otherScope).decode(encoded, &decoded, sessionTokenType); err == nil {
		t.Fatal("accepted a different function scope")
	}

	parts := strings.Split(encoded, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString(append(payload, ' '))
	if err := codec.decode(strings.Join(parts, "."), &decoded, sessionTokenType); err == nil {
		t.Fatal("accepted tampered JWT")
	}
	for _, value := range []string{"", "plaintext", "v1.old-cookie", "a.b.c", strings.Repeat("x", maxCookieValueBytes+1)} {
		if err := codec.decode(value, &decoded, sessionTokenType); err == nil {
			t.Fatal("accepted malformed cookie")
		}
	}
}

func TestCookieRejectsInvalidClaims(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	codec := testCodec(t, cfg)
	for name, change := range map[string]func(*sessionClaims){
		"wrong issuer":       func(c *sessionClaims) { c.Issuer = "https://other.example/auth" },
		"missing issuer":     func(c *sessionClaims) { c.Issuer = "" },
		"wrong audience":     func(c *sessionClaims) { c.Audience = jwt.ClaimStrings{"https://other.example/function"} },
		"missing audience":   func(c *sessionClaims) { c.Audience = nil },
		"multiple audiences": func(c *sessionClaims) { c.Audience = append(c.Audience, "https://other.example/function") },
		"expired":            func(c *sessionClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Second)) },
		"missing expiry":     func(c *sessionClaims) { c.ExpiresAt = nil },
		"missing issued at":  func(c *sessionClaims) { c.IssuedAt = nil },
		"future issued at":   func(c *sessionClaims) { c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour)) },
		"wrong type":         func(c *sessionClaims) { c.Type = loginTokenType },
		"missing type":       func(c *sessionClaims) { c.Type = "" },
	} {
		t.Run(name, func(t *testing.T) {
			claims := testSessionClaims(t, codec, sessionClaims{}, time.Now().Add(time.Hour))
			change(&claims)
			encoded := signCookieClaims(t, &claims, jwt.SigningMethodHS256, codec.signingKey)
			var decoded sessionClaims
			if err := codec.decode(encoded, &decoded, sessionTokenType); err == nil {
				t.Fatal("accepted invalid signed claims")
			}
		})
	}

	claims := testSessionClaims(t, codec, sessionClaims{}, time.Now().Add(time.Hour))
	for _, tc := range []struct {
		method jwt.SigningMethod
		key    any
	}{
		{jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType},
		{jwt.SigningMethodHS384, codec.signingKey},
	} {
		var decoded sessionClaims
		if err := codec.decode(signCookieClaims(t, &claims, tc.method, tc.key), &decoded, sessionTokenType); err == nil {
			t.Fatal("accepted disallowed signing algorithm")
		}
	}
}

func TestLoginCookieCannotBecomeSession(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	login := testLoginToken(t, cfg, loginSession{State: "state", Verifier: "verifier"}, time.Now().Add(time.Minute))
	var session sessionClaims
	if err := testCodec(t, cfg).decode(login, &session, sessionTokenType); err == nil {
		t.Fatal("accepted an anonymously issued login JWT as a session")
	}
}

func TestCookieExpiryAndSize(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	codec := testCodec(t, cfg)
	if _, err := codec.claims(time.Now().Add(-time.Second)); err == nil {
		t.Fatal("issued expired claims")
	}
	claims := testSessionClaims(t, codec, sessionClaims{FederatedName: strings.Repeat("x", maxCookieValueBytes)}, time.Now().Add(time.Hour))
	if _, err := codec.encode(&claims); err == nil {
		t.Fatal("issued oversized cookie")
	}
}

func TestSessionGroupsAreMarkedWhenTruncated(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	codec := testCodec(t, cfg)
	groups := make([]string, 100)
	for i := range groups {
		groups[i] = strings.Repeat("g", 40) + fmt.Sprint(i)
	}
	identity := testSessionClaims(t, codec, sessionClaims{FederatedGroups: groups}, time.Now().Add(time.Hour))
	h := OAuthHandler{tokens: codec}
	encoded, err := h.encodeSession(&identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > maxCookieValueBytes {
		t.Fatal("truncated session still exceeds the cookie limit")
	}
	var decoded sessionClaims
	if err := codec.decode(encoded, &decoded, sessionTokenType); err != nil {
		t.Fatal(err)
	}
	if !decoded.GroupsTruncated || len(decoded.FederatedGroups) == 0 || len(decoded.FederatedGroups) >= len(groups) {
		t.Fatalf("groups were not safely marked and truncated: %+v", decoded)
	}
	if !reflect.DeepEqual(decoded.FederatedGroups, groups[:len(decoded.FederatedGroups)]) {
		t.Fatal("group truncation did not preserve provider order")
	}
}

func TestSessionGroupAllowlistRunsBeforeSizeTruncation(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	codec := testCodec(t, cfg)
	groups := make([]string, 100)
	for i := range groups {
		groups[i] = strings.Repeat("g", 40) + fmt.Sprint(i)
	}
	selected := filterGroups(groups, []string{groups[99], groups[98], "missing"})
	if !reflect.DeepEqual(selected, []string{groups[98], groups[99]}) {
		t.Fatalf("allowlist did not preserve provider order: %v", selected)
	}
	identity := testSessionClaims(t, codec, sessionClaims{FederatedGroups: selected}, time.Now().Add(time.Hour))
	h := OAuthHandler{tokens: codec}
	encoded, err := h.encodeSession(&identity)
	if err != nil {
		t.Fatal(err)
	}
	var decoded sessionClaims
	if err := codec.decode(encoded, &decoded, sessionTokenType); err != nil {
		t.Fatal(err)
	}
	if decoded.GroupsTruncated || !reflect.DeepEqual(decoded.FederatedGroups, selected) {
		t.Fatalf("selected groups should fit without truncation: %+v", decoded)
	}
}

func TestCookieRejectsInvalidKey(t *testing.T) {
	for _, size := range []int{0, 16, 24, 31, 33} {
		if _, err := newCookieCodec(make([]byte, size), "https://example.com"); err == nil {
			t.Fatalf("accepted key length %d", size)
		}
	}
}

func testCodec(t *testing.T, cfg Config) *cookieCodec {
	t.Helper()
	codec, err := newCookieCodec(cfg.CookieSecret, cfg.BaseURL.String())
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func testSessionClaims(t *testing.T, codec *cookieCodec, session sessionClaims, expires time.Time) sessionClaims {
	t.Helper()
	subject := session.Subject
	claims, err := codec.claims(expires)
	if err != nil {
		t.Fatal(err)
	}
	session.RegisteredClaims = claims
	session.Subject = subject
	session.Type = sessionTokenType
	return session
}

func testSessionToken(t *testing.T, cfg Config, session sessionClaims, expires time.Time) string {
	t.Helper()
	codec := testCodec(t, cfg)
	session = testSessionClaims(t, codec, session, expires)
	encoded, err := codec.encode(&session)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func testSession(subject string) sessionClaims {
	session := sessionClaims{}
	session.Subject = subject
	return session
}

func testLoginToken(t *testing.T, cfg Config, login loginSession, expires time.Time) string {
	t.Helper()
	codec := testCodec(t, cfg)
	claims, err := codec.claims(expires)
	if err != nil {
		t.Fatal(err)
	}
	login.RegisteredClaims = claims
	login.Type = loginTokenType
	encoded, err := codec.encode(&login)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func signCookieClaims(t *testing.T, claims jwt.Claims, method jwt.SigningMethod, key any) string {
	t.Helper()
	encoded, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
