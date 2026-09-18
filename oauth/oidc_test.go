package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rakutentech/jwk-go/jwk"
)

type oidcFixture struct {
	server      *httptest.Server
	key         *rsa.PrivateKey
	cfg         Config
	token       atomic.Value
	keySet      atomic.Value
	keyRequests atomic.Int32
	keyStatus   atomic.Int32
}

func newOIDCFixture(t *testing.T, change func(*openIDConfiguration)) *oidcFixture {
	t.Helper()
	return newOIDCFixtureWithHTTP(t, change, false)
}

func newOIDCFixtureWithHTTP(t *testing.T, change func(*openIDConfiguration), allowHTTP bool) *oidcFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &oidcFixture{key: key}
	f.token.Store(map[string]string{"access_token": "opaque"})
	f.keySet.Store(jwk.KeySpecSet{Keys: []jwk.KeySpec{{Key: &key.PublicKey, KeyID: "first", Use: "sig", Algorithm: "RS256"}}})
	f.keyStatus.Store(http.StatusOK)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tenant/.well-known/openid-configuration":
			metadata := openIDConfiguration{Issuer: f.server.URL + "/tenant", AuthorizationEndpoint: f.server.URL + "/authorize", TokenEndpoint: f.server.URL + "/token", JWKSURI: f.server.URL + "/keys", SigningAlgorithms: []string{"RS256"}}
			if change != nil {
				change(&metadata)
			}
			json.NewEncoder(w).Encode(metadata)
		case "/keys":
			f.keyRequests.Add(1)
			w.WriteHeader(int(f.keyStatus.Load()))
			json.NewEncoder(w).Encode(f.keySet.Load())
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("redirect_uri") != "https://example.com/function/my-fn/auth/callback" {
				t.Error("wrong callback URI")
			}
			json.NewEncoder(w).Encode(f.token.Load())
		default:
			http.NotFound(w, r)
		}
	}))
	if allowHTTP {
		f.server.Start()
	} else {
		f.server.StartTLS()
	}
	t.Cleanup(f.server.Close)
	f.cfg = testConfig("https://ignored.example/authorize", "https://ignored.example/token")
	f.cfg.AllowHTTP = allowHTTP
	f.cfg.IssuerURL = f.server.URL + "/tenant"
	f.cfg.Scopes = []string{"profile"}
	return f
}

func (f *oidcFixture) claims() jwt.MapClaims {
	return jwt.MapClaims{"iss": f.cfg.IssuerURL, "aud": f.cfg.ClientID, "sub": "alice", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
}

func signIDToken(t *testing.T, claims jwt.MapClaims, key any, kid any, method jwt.SigningMethod) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != nil {
		token.Header["kid"] = kid
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *oidcFixture) client(t *testing.T) *OIDCClient {
	t.Helper()
	client, err := NewOIDCClient(f.cfg, f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestOIDCDiscoveryAndExchange(t *testing.T) {
	f := newOIDCFixture(t, nil)
	client := f.client(t)
	authURL, err := url.Parse(client.AuthorizationURL("state", "challenge"))
	if err != nil {
		t.Fatal(err)
	}
	if authURL.Scheme+"://"+authURL.Host+authURL.Path != f.server.URL+"/authorize" {
		t.Fatalf("wrong discovered authorization endpoint: %s", authURL)
	}
	if authURL.Query().Get("scope") != "openid profile" {
		t.Fatal("missing openid scope")
	}
	raw := signIDToken(t, f.claims(), f.key, "first", jwt.SigningMethodRS256)
	f.token.Store(map[string]string{"id_token": raw, "access_token": "opaque"})
	token, err := client.Exchange(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	if token.IDToken != raw || token.AccessToken != "opaque" {
		t.Fatal("token response not preserved")
	}
	for range 2 {
		if _, err := client.VerifyIDToken(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
	}
	if f.keyRequests.Load() != 1 {
		t.Fatal("JWKS not cached")
	}
}

func TestOIDCRejectsInvalidDiscovery(t *testing.T) {
	for name, change := range map[string]func(*openIDConfiguration){
		"issuer mismatch":        func(m *openIDConfiguration) { m.Issuer += "/other" },
		"missing issuer":         func(m *openIDConfiguration) { m.Issuer = "" },
		"insecure authorization": func(m *openIDConfiguration) { m.AuthorizationEndpoint = "http://example.com/authorize" },
		"missing token endpoint": func(m *openIDConfiguration) { m.TokenEndpoint = "" },
		"insecure keys":          func(m *openIDConfiguration) { m.JWKSURI = "http://example.com/keys" },
		"unsigned only":          func(m *openIDConfiguration) { m.SigningAlgorithms = []string{"none"} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newOIDCFixture(t, change)
			if _, err := NewOIDCClient(f.cfg, f.server.Client()); err == nil {
				t.Fatal("accepted invalid discovery")
			}
		})
	}
}

func TestOIDCRejectsInvalidIDTokens(t *testing.T) {
	f := newOIDCFixture(t, nil)
	client := f.client(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(jwt.MapClaims){
		"issuer":                         func(c jwt.MapClaims) { c["iss"] = "https://other.example" },
		"audience":                       func(c jwt.MapClaims) { c["aud"] = "other-client" },
		"expired":                        func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"missing expiry":                 func(c jwt.MapClaims) { delete(c, "exp") },
		"missing issuer":                 func(c jwt.MapClaims) { delete(c, "iss") },
		"missing audience":               func(c jwt.MapClaims) { delete(c, "aud") },
		"missing subject":                func(c jwt.MapClaims) { delete(c, "sub") },
		"missing issued at":              func(c jwt.MapClaims) { delete(c, "iat") },
		"future issued at":               func(c jwt.MapClaims) { c["iat"] = time.Now().Add(time.Hour).Unix() },
		"not yet valid":                  func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() },
		"authorized party":               func(c jwt.MapClaims) { c["azp"] = "other-client" },
		"multiple audiences without azp": func(c jwt.MapClaims) { c["aud"] = []string{f.cfg.ClientID, "another-client"} },
	} {
		t.Run(name, func(t *testing.T) {
			claims := f.claims()
			change(claims)
			raw := signIDToken(t, claims, f.key, "first", jwt.SigningMethodRS256)
			if _, err := client.VerifyIDToken(context.Background(), raw); err == nil {
				t.Fatal("accepted invalid claims")
			}
		})
	}
	for name, raw := range map[string]string{
		"bad signature":  signIDToken(t, f.claims(), otherKey, "first", jwt.SigningMethodRS256),
		"unknown key":    signIDToken(t, f.claims(), f.key, "unknown", jwt.SigningMethodRS256),
		"missing kid":    signIDToken(t, f.claims(), f.key, nil, jwt.SigningMethodRS256),
		"non-string kid": signIDToken(t, f.claims(), f.key, 42, jwt.SigningMethodRS256),
		"HMAC":           signIDToken(t, f.claims(), []byte("secret"), "first", jwt.SigningMethodHS256),
		"unsigned":       signIDToken(t, f.claims(), jwt.UnsafeAllowNoneSignatureType, "first", jwt.SigningMethodNone),
		"malformed":      "invalid",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.VerifyIDToken(context.Background(), raw); err == nil {
				t.Fatal("accepted invalid token")
			}
		})
	}
	claims := f.claims()
	claims["aud"] = []string{f.cfg.ClientID, "other"}
	claims["azp"] = f.cfg.ClientID
	if _, err := client.VerifyIDToken(context.Background(), signIDToken(t, claims, f.key, "first", jwt.SigningMethodRS256)); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCCallbackOnlyIssuesCookieAfterVerification(t *testing.T) {
	f := newOIDCFixture(t, nil)
	client := f.client(t)
	handler, err := NewOAuthHandler(f.cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	raw := signIDToken(t, f.claims(), f.key, "first", jwt.SigningMethodRS256)
	for _, tc := range []struct {
		name, idToken, accessToken string
		status                     int
	}{
		{"valid", raw, "opaque", http.StatusSeeOther},
		{"invalid", "invalid", raw, http.StatusUnauthorized},
		{"access token only", "", raw, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.token.Store(map[string]string{"id_token": tc.idToken, "access_token": tc.accessToken})
			req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=state", nil)
			stateCookie, err := testCodec(t, f.cfg).Encode(f.cfg.LoginCookie, loginSession{State: "state", Verifier: "verifier"}, time.Now().Add(defaultStateLifetime))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(&http.Cookie{Name: f.cfg.LoginCookie, Value: stateCookie})
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.status {
				t.Fatalf("status %d, want %d", res.Code, tc.status)
			}
			session := false
			for _, cookie := range res.Result().Cookies() {
				if cookie.Name == f.cfg.CookieName {
					session = true
				}
			}
			if session != (tc.status == http.StatusSeeOther) {
				t.Fatal("session issued without successful verification, or missing after success")
			}
		})
	}
}

func TestOIDCKeyRefresh(t *testing.T) {
	f := newOIDCFixture(t, nil)
	client := f.client(t)
	old := signIDToken(t, f.claims(), f.key, "first", jwt.SigningMethodRS256)
	if _, err := client.VerifyIDToken(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	f.keySet.Store(jwk.KeySpecSet{Keys: []jwk.KeySpec{{Key: &f.key.PublicKey, KeyID: "second", Algorithm: "RS256", Use: "sig"}}})
	client.keys.updated = time.Now().Add(-jwksCacheLifetime)
	if _, err := client.VerifyIDToken(context.Background(), old); err == nil {
		t.Fatal("removed key remains trusted")
	}
	next := signIDToken(t, f.claims(), f.key, "second", jwt.SigningMethodRS256)
	if _, err := client.VerifyIDToken(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	f.keyStatus.Store(http.StatusServiceUnavailable)
	client.keys.updated = time.Now().Add(-jwksCacheLifetime)
	if _, err := client.VerifyIDToken(context.Background(), next); err == nil {
		t.Fatal("accepted stale keys after refresh failure")
	}
}

func TestOIDCJSONCancellationAndBodyLimit(t *testing.T) {
	f := newOIDCFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var metadata openIDConfiguration
	if err := getOIDCJSON(ctx, f.server.Client(), f.cfg.IssuerURL+"/.well-known/openid-configuration", &metadata); err == nil {
		t.Fatal("ignored canceled context")
	}
	for _, body := range []string{"not JSON", strings.Repeat(" ", maxBodyBytes+1)} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		cfg := f.cfg
		cfg.IssuerURL = server.URL
		_, err := NewOIDCClient(cfg, server.Client())
		server.Close()
		if err == nil {
			t.Fatal("accepted invalid discovery response")
		}
	}
}

func TestOIDCRejectsUnsuitableKeys(t *testing.T) {
	for _, tc := range []struct{ name, use, alg string }{
		{"encryption key", "enc", "RS256"},
		{"algorithm mismatch", "sig", "RS512"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOIDCFixture(t, nil)
			f.keySet.Store(jwk.KeySpecSet{Keys: []jwk.KeySpec{{Key: &f.key.PublicKey, KeyID: "first", Use: tc.use, Algorithm: tc.alg}}})
			client := f.client(t)
			raw := signIDToken(t, f.claims(), f.key, "first", jwt.SigningMethodRS256)
			if _, err := client.VerifyIDToken(context.Background(), raw); err == nil {
				t.Fatal("accepted unsuitable signing key")
			}
		})
	}
}

func TestClientSelection(t *testing.T) {
	cfg := testConfig("https://example.com/authorize", "https://example.com/token")
	client, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := client.(*OAuthClient); !ok {
		t.Fatal("explicit endpoints should select OAuth")
	}
	f := newOIDCFixture(t, nil)
	client, err = NewClient(f.cfg, f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := client.(*OIDCClient); !ok {
		t.Fatal("issuer URL should select OIDC")
	}
}

func TestOIDCConcurrentVerification(t *testing.T) {
	f := newOIDCFixture(t, nil)
	client := f.client(t)
	raw := signIDToken(t, f.claims(), f.key, "first", jwt.SigningMethodRS256)
	results := make(chan error, 10)
	for range 10 {
		go func() { _, err := client.VerifyIDToken(context.Background(), raw); results <- err }()
	}
	for range 10 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if f.keyRequests.Load() != 1 {
		t.Fatal("concurrent verification should share cached keys")
	}
}

func TestOIDCES256(t *testing.T) {
	f := newOIDCFixture(t, func(m *openIDConfiguration) { m.SigningAlgorithms = []string{"ES256"} })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.keySet.Store(jwk.KeySpecSet{Keys: []jwk.KeySpec{{Key: &key.PublicKey, KeyID: "ec-key", Use: "sig", Algorithm: "ES256"}}})
	client := f.client(t)
	raw := signIDToken(t, f.claims(), key, "ec-key", jwt.SigningMethodES256)
	f.token.Store(map[string]string{"id_token": raw, "access_token": "opaque"})
	if _, err := client.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCRejectsHTTPRedirect(t *testing.T) {
	var insecureRequests atomic.Int32
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { insecureRequests.Add(1) }))
	defer insecure.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, insecure.URL, http.StatusFound) }))
	defer secure.Close()
	cfg := testConfig("https://example.com/authorize", "https://example.com/token")
	cfg.IssuerURL = secure.URL
	if _, err := NewOIDCClient(cfg, secure.Client()); err == nil {
		t.Fatal("accepted insecure discovery redirect")
	}
	if insecureRequests.Load() != 0 {
		t.Fatal("followed insecure redirect")
	}
}

func TestOIDCWithHTTPProvider(t *testing.T) {
	f := newOIDCFixtureWithHTTP(t, nil, true)
	f.token.Store(map[string]string{"id_token": signIDToken(t, f.claims(), f.key, "first", jwt.SigningMethodRS256)})
	client := f.client(t)
	if _, err := client.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatal(err)
	}
	if f.keyRequests.Load() != 1 {
		t.Fatal("expected ID token verification using HTTP JWKS endpoint")
	}
	f.cfg.AllowHTTP = false
	if _, err := NewOIDCClient(f.cfg, f.server.Client()); err == nil {
		t.Fatal("accepted HTTP issuer without development opt-in")
	}
}

func TestOIDCDiscoveredHTTPEndpoints(t *testing.T) {
	for _, field := range []string{"authorization", "token", "jwks"} {
		t.Run(field, func(t *testing.T) {
			f := newOIDCFixture(t, func(metadata *openIDConfiguration) {
				switch field {
				case "authorization":
					metadata.AuthorizationEndpoint = "http://provider.test/authorize"
				case "token":
					metadata.TokenEndpoint = "http://provider.test/token"
				case "jwks":
					metadata.JWKSURI = "http://provider.test/keys"
				}
			})
			if _, err := NewOIDCClient(f.cfg, f.server.Client()); err == nil {
				t.Fatal("accepted discovered HTTP endpoint without opt-in")
			}
			f.cfg.AllowHTTP = true
			if _, err := NewOIDCClient(f.cfg, f.server.Client()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
