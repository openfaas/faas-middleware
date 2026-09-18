package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeJWT builds an unsigned-looking JWT (header.payload.signature) with the
// given claims. The signature is arbitrary because verification is deferred.
func fakeJWT(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("signature"))
}

var testCookieSecret = []byte("0123456789abcdef0123456789abcdef")

func testConfig(authorization, token string) Config {
	baseURL, _ := url.Parse("https://example.com/function/my-fn")
	authURL, _ := url.Parse(authorization)
	tokenURL, _ := url.Parse(token)
	return Config{
		BaseURL:               baseURL,
		CookieSecret:          testCookieSecret,
		ClientID:              "my-fn",
		ClientSecret:          "secret",
		AuthorizationEndpoint: authURL,
		TokenEndpoint:         tokenURL,
		Scopes:                []string{"openid"},
		CookieName:            "of_session",
		LoginCookie:           "of_login",
	}
}

func testHandler(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	client, err := NewOAuthClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewOAuthHandler(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestLoginRedirectsToAuthorizationEndpointWithStateCookie(t *testing.T) {
	handler := testHandler(t, testConfig("https://issuer.example.com/authorize", "https://issuer.example.com/token"))

	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	if res.Code != http.StatusFound {
		t.Fatalf("login returned %d, want 302", res.Code)
	}
	location := res.Header().Get("Location")
	if !strings.HasPrefix(location, "https://issuer.example.com/authorize?") {
		t.Fatalf("unexpected redirect: %s", location)
	}
	if !strings.Contains(location, "scope=openid") {
		t.Fatalf("missing default scope in redirect: %s", location)
	}

	cookie := res.Result().Cookies()[0]
	if cookie.Name != "of_login" {
		t.Fatalf("unexpected cookie name: %s", cookie.Name)
	}
	var state loginSession
	cfg := testConfig("https://issuer.example.com/authorize", "https://issuer.example.com/token")
	if err := testCodec(t, cfg).Decode(cfg.LoginCookie, cookie.Value, &state); err != nil {
		t.Fatal(err)
	}
	if state.State == "" || state.State != loginState(t, res) || cookie.Value == state.State {
		t.Fatal("login cookie must protect the redirect state")
	}
	if !cookie.HttpOnly {
		t.Fatal("login cookie must be HttpOnly")
	}
}

func TestLoginRejectsNonGet(t *testing.T) {
	handler := testHandler(t, testConfig("https://issuer.example.com/authorize", "https://issuer.example.com/token"))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/auth/login", nil))
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("login POST returned %d, want 405", res.Code)
	}
}

func TestCallbackIssuesSessionCookie(t *testing.T) {
	var issuedJWT string
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "abc" {
			t.Error("invalid authorization code grant")
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "my-fn" || pass != "secret" {
			t.Error("invalid client credentials")
		}
		issuedJWT = fakeJWT(map[string]any{
			"sub": "welteki",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"access_token": issuedJWT, "token_type": "Bearer"})
	}))
	defer tokenEndpoint.Close()

	cfg := testConfig("https://issuer.example.com/authorize", tokenEndpoint.URL)
	cfg.AllowHTTP = true
	handler := testHandler(t, cfg)

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	loginCookie := login.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+loginState(t, login), nil)
	req.AddCookie(loginCookie)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusSeeOther {
		t.Fatalf("callback returned %d, want 303: %s", res.Code, res.Body)
	}
	if res.Header().Get("Location") != "https://example.com/function/my-fn" {
		t.Fatalf("callback redirects to %q, want the configured base URL", res.Header().Get("Location"))
	}
	found := false
	for _, c := range res.Result().Cookies() {
		if c.Name == "of_session" {
			found = true
			if !c.HttpOnly {
				t.Fatal("session cookie must be HttpOnly")
			}
			var token Token
			if err := testCodec(t, cfg).Decode(cfg.CookieName, c.Value, &token); err != nil {
				t.Fatal(err)
			}
			if len(strings.Split(c.Value, ".")) != 3 {
				t.Fatal("browser cookie must use the signed JWT wrapper")
			}
			if token.AccessToken != issuedJWT {
				t.Fatalf("session cookie must carry the access token verbatim")
			}
			claims, err := parseJWT(token.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			if claims["sub"] != "welteki" {
				t.Fatalf("unexpected session subject: %v", claims["sub"])
			}
		}
	}
	if !found {
		t.Fatal("no session cookie issued")
	}
}

func TestCallbackIssuesSessionCookieWithIDToken(t *testing.T) {
	var issuedJWT string
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuedJWT = fakeJWT(map[string]any{
			"sub": "welteki",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"id_token": issuedJWT, "access_token": "opaque", "token_type": "Bearer"})
	}))
	defer tokenEndpoint.Close()

	cfg := testConfig("https://issuer.example.com/authorize", tokenEndpoint.URL)
	cfg.AllowHTTP = true
	cfg.LoginRedirect = "https://example.com/function/my-fn/dashboard"
	handler := testHandler(t, cfg)

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	loginCookie := login.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+loginState(t, login), nil)
	req.AddCookie(loginCookie)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusSeeOther {
		t.Fatalf("callback returned %d, want 303: %s", res.Code, res.Body)
	}
	if res.Header().Get("Location") != cfg.LoginRedirect {
		t.Fatalf("callback redirects to %q, want the configured login redirect", res.Header().Get("Location"))
	}
	for _, c := range res.Result().Cookies() {
		if c.Name == "of_session" {
			var token Token
			if err := testCodec(t, cfg).Decode(cfg.CookieName, c.Value, &token); err != nil {
				t.Fatal(err)
			}
			if len(strings.Split(c.Value, ".")) != 3 {
				t.Fatal("browser cookie must use the signed JWT wrapper")
			}
			if token.IDToken != issuedJWT {
				t.Fatalf("session cookie must carry the ID token verbatim")
			}
			var fields map[string]string
			if err := testCodec(t, cfg).Decode(cfg.CookieName, c.Value, &fields); err != nil {
				t.Fatal(err)
			}
			if len(fields) != 2 || fields["id_token"] != issuedJWT || fields["access_token"] != "opaque" {
				t.Fatal("session cookie must use OAuth JSON field names")
			}
			return
		}
	}
	t.Fatal("no session cookie issued")
}

func TestCallbackRejectsMismatchedState(t *testing.T) {
	handler := testHandler(t, testConfig("https://issuer.example.com/authorize", "https://issuer.example.com/token"))
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=wrong", nil)
	req.AddCookie(&http.Cookie{Name: "of_login", Value: "other"})
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("callback with bad state returned %d, want 400", res.Code)
	}
}

func TestLogoutClearsCookies(t *testing.T) {
	handler := testHandler(t, testConfig("https://issuer.example.com/authorize", "https://issuer.example.com/token"))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))
	if res.Code != http.StatusSeeOther {
		t.Fatalf("logout returned %d, want 303", res.Code)
	}
	if res.Header().Get("Location") != "https://example.com/function/my-fn/auth/login" {
		t.Fatalf("logout redirects to %q, want the default login path", res.Header().Get("Location"))
	}
	for _, c := range res.Result().Cookies() {
		if c.MaxAge >= 0 {
			t.Fatalf("cookie %s was not cleared", c.Name)
		}
	}
}

func testCodec(t *testing.T, cfg Config) *CookieCodec {
	t.Helper()
	codec, err := NewCookieCodec(cfg.CookieSecret, cfg.BaseURL.String())
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func loginState(t *testing.T, res *httptest.ResponseRecorder) string {
	t.Helper()
	u, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state")
}

func TestCallbackRejectsExpiredIdentity(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"id_token": fakeJWT(map[string]any{"sub": "alice", "exp": time.Now().Add(-time.Minute).Unix()})})
	}))
	defer endpoint.Close()
	cfg := testConfig("https://issuer.example.com/authorize", endpoint.URL)
	cfg.AllowHTTP = true
	handler := testHandler(t, cfg)
	state, err := testCodec(t, cfg).Encode(cfg.LoginCookie, loginSession{State: "state", Verifier: "verifier"}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=state", nil)
	req.AddCookie(&http.Cookie{Name: cfg.LoginCookie, Value: state})
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expired identity returned %d", res.Code)
	}
	for _, cookie := range res.Result().Cookies() {
		if cookie.Name == cfg.CookieName {
			t.Fatal("issued a session for an expired identity")
		}
	}
}

func TestCallbackRejectsForgedStateCookie(t *testing.T) {
	cfg := testConfig("https://issuer.example.com/authorize", "https://issuer.example.com/token")
	handler := testHandler(t, cfg)
	// Matching a caller-written plaintext cookie to the query no longer suffices.
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=state", nil)
	req.AddCookie(&http.Cookie{Name: cfg.LoginCookie, Value: "state"})
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("forged state returned %d", res.Code)
	}
}

func TestCallbackOpaqueOAuthToken(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Header.Get("Accept") != "application/json" || r.Header.Get("Authorization") != "" || r.PostForm.Get("client_id") != "my-fn" || r.PostForm.Get("client_secret") != "secret" {
			t.Error("expected JSON negotiation and client_secret_post authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"gho_opaque-token","expires_in":120}`))
	}))
	defer endpoint.Close()
	cfg := testConfig("https://github.com/login/oauth/authorize", endpoint.URL)
	cfg.AllowHTTP = true
	cfg.TokenAuthMethod = "client_secret_post"
	handler := testHandler(t, cfg)
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+loginState(t, login), nil)
	req.AddCookie(login.Result().Cookies()[0])
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusSeeOther {
		t.Fatalf("callback status %d: %s", res.Code, res.Body)
	}
	for _, cookie := range res.Result().Cookies() {
		if cookie.Name != cfg.CookieName {
			continue
		}
		var token Token
		if err := testCodec(t, cfg).Decode(cfg.CookieName, cookie.Value, &token); err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Expires int64 `json:"exp"`
		}
		payload, err := base64.RawURLEncoding.DecodeString(strings.Split(cookie.Value, ".")[1])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		if cookie.Expires.Unix() != claims.Expires {
			t.Fatal("cookie and wrapper expiry differ")
		}
		if token.AccessToken != "gho_opaque-token" || cookie.MaxAge != 0 || time.Until(cookie.Expires) > 120*time.Second || time.Until(cookie.Expires) < 115*time.Second {
			t.Fatalf("unexpected opaque token or lifetime: %d", cookie.MaxAge)
		}
		return
	}
	t.Fatal("missing session cookie")
}

func TestCookiePath(t *testing.T) {
	for _, tc := range []struct{ base, path string }{
		{"https://example.com/function/my-fn", "/function/my-fn"},
		{"https://example.com/function/my-fn/", "/function/my-fn"},
		{"https://example.com", "/"},
		{"https://example.com/", "/"},
	} {
		t.Run(tc.base, func(t *testing.T) {
			cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
			cfg.BaseURL, _ = url.Parse(tc.base)
			h, err := NewOAuthHandler(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			jar, _ := cookiejar.New(nil)
			origin, _ := url.Parse(tc.base)
			res := httptest.NewRecorder()
			h.setCookie(res, cfg.CookieName, "signed-session", time.Now().Add(time.Hour))
			h.setCookie(res, cfg.LoginCookie, "signed-state", time.Now().Add(10*time.Minute))
			cookies := res.Result().Cookies()
			for _, cookie := range cookies {
				if cookie.Path != tc.path {
					t.Fatalf("cookie path %q, want %q", cookie.Path, tc.path)
				}
			}
			jar.SetCookies(origin, cookies)
			for _, suffix := range []string{"", "/", "/auth/callback", "/auth/logout"} {
				target, _ := url.Parse("https://example.com" + strings.TrimRight(tc.path, "/") + suffix)
				if len(jar.Cookies(target)) != 2 {
					t.Fatalf("cookies unavailable at %s", target)
				}
			}
			if tc.path != "/" {
				for _, path := range []string{"/", "/function/other", "/function/my-fn-other"} {
					target, _ := url.Parse("https://example.com" + path)
					if len(jar.Cookies(target)) != 0 {
						t.Fatalf("cookies leaked to %s", target)
					}
				}
			}
			logout := httptest.NewRecorder()
			h.ServeHTTP(logout, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))
			for _, cookie := range logout.Result().Cookies() {
				if cookie.Path != tc.path || cookie.MaxAge >= 0 {
					t.Fatal("logout must clear cookies at the same path")
				}
			}
			jar.SetCookies(origin, logout.Result().Cookies())
			if len(jar.Cookies(origin)) != 0 {
				t.Fatal("logout left cookies behind")
			}
		})
	}
}

type errorRedirectClient struct {
	token  Token
	err    error
	called bool
}

func (c *errorRedirectClient) AuthorizationURL(string, string) string {
	return "https://issuer.example/authorize"
}
func (c *errorRedirectClient) Exchange(context.Context, string, string) (Token, error) {
	c.called = true
	return c.token, c.err
}

func TestCallbackErrorRedirect(t *testing.T) {
	for _, tc := range []struct {
		name, query  string
		token        Token
		err          error
		status       int
		skipExchange bool
	}{
		{name: "invalid state", query: "code=code&state=wrong", status: 400, skipExchange: true},
		{name: "provider denial", query: "error=access_denied&code=code&state=state", status: 400, skipExchange: true},
		{name: "exchange failure", err: errors.New("sensitive provider details"), status: 502},
		{name: "invalid ID token", err: ErrInvalidIDToken, status: 401},
		{name: "expired identity", token: Token{IDToken: fakeJWT(map[string]any{"sub": "user", "exp": time.Now().Add(-time.Hour).Unix()})}, status: 401},
		{name: "oversized session", token: Token{AccessToken: strings.Repeat("x", maxCookieValueBytes)}, status: 500},
	} {
		for _, redirect := range []string{"", "https://example.com/function/my-fn/login-error"} {
			t.Run(tc.name+"/"+redirect, func(t *testing.T) {
				cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
				cfg.ErrorRedirect = redirect
				client := &errorRedirectClient{token: tc.token, err: tc.err}
				h, err := NewOAuthHandler(cfg, client)
				if err != nil {
					t.Fatal(err)
				}
				state, err := testCodec(t, cfg).Encode(cfg.LoginCookie, loginSession{State: "state", Verifier: "verifier"}, time.Now().Add(time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				query := tc.query
				if query == "" {
					query = "code=code&state=state"
				}
				req := httptest.NewRequest(http.MethodGet, "/auth/callback?"+query, nil)
				req.AddCookie(&http.Cookie{Name: cfg.LoginCookie, Value: state})
				res := httptest.NewRecorder()
				h.ServeHTTP(res, req)
				if redirect != "" {
					if res.Code != http.StatusSeeOther || res.Header().Get("Location") != redirect {
						t.Fatalf("unexpected redirect: %d %q", res.Code, res.Header().Get("Location"))
					}
					if res.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("error redirect must not be cached")
					}
				} else if res.Code != tc.status || res.Header().Get("Location") != "" {
					t.Fatalf("unexpected fallback response: %d", res.Code)
				}
				if strings.Contains(res.Body.String(), "sensitive provider details") {
					t.Fatal("provider details exposed")
				}
				if client.called == tc.skipExchange {
					t.Fatal("unexpected token exchange")
				}
				for _, cookie := range res.Result().Cookies() {
					if cookie.Name == cfg.CookieName && cookie.MaxAge >= 0 {
						t.Fatal("issued session on failure")
					}
				}
			})
		}
	}
}

func TestLoginCreationErrorRedirect(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	cfg.ErrorRedirect = "https://example.com/function/my-fn/login-error"
	cfg.LoginCookie = strings.Repeat("x", maxCookieValueBytes)
	h, err := NewOAuthHandler(cfg, &errorRedirectClient{})
	if err != nil {
		t.Fatal(err)
	}
	res := httptest.NewRecorder()
	h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if res.Code != 303 || res.Header().Get("Location") != cfg.ErrorRedirect {
		t.Fatal("login creation failure did not redirect")
	}
}

func TestPKCELoginAndExchange(t *testing.T) {
	for _, oidc := range []bool{false, true} {
		for _, method := range []string{"", "client_secret_basic", "client_secret_post"} {
			for _, secret := range []string{"", "secret"} {
				name := "oauth"
				if oidc {
					name = "oidc"
				}
				t.Run(name+"/"+method+"/secret="+secret, func(t *testing.T) {
					var challenge string
					var exchanged bool
					var response Token
					endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						exchanged = true
						if err := r.ParseForm(); err != nil {
							t.Error(err)
						}
						verifier := r.Form.Get("code_verifier")
						raw, err := base64.RawURLEncoding.DecodeString(verifier)
						if err != nil || len(raw) != 32 {
							t.Error("expected a random 32-byte verifier encoded as base64url")
						}
						sum := sha256.Sum256([]byte(verifier))
						if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
							t.Error("verifier does not match the login challenge")
							http.Error(w, "invalid_grant", http.StatusBadRequest)
							return
						}
						if r.Form.Get("code") != "code" || r.Form.Get("grant_type") != "authorization_code" {
							t.Error("wrong authorization code grant")
						}
						if secret == "" {
							if r.Header.Get("Authorization") != "" || r.Form.Has("client_secret") || r.Form.Get("client_id") != "my-fn" {
								t.Error("public client must send its client ID without credentials")
							}
						} else if method == "client_secret_post" {
							if r.Header.Get("Authorization") != "" || r.Form.Get("client_id") != "my-fn" || r.Form.Get("client_secret") != secret {
								t.Error("incorrect POST client authentication")
							}
						} else {
							id, password, ok := r.BasicAuth()
							if !ok || id != "my-fn" || password != secret || r.Form.Has("client_secret") {
								t.Error("incorrect Basic client authentication")
							}
						}
						json.NewEncoder(w).Encode(response)
					}))
					defer endpoint.Close()
					cfg := testConfig("https://issuer.example/authorize", endpoint.URL)
					cfg.ClientSecret = secret
					cfg.TokenAuthMethod = method
					httpClient := endpoint.Client()
					response = Token{AccessToken: "access-token"}
					if oidc {
						f := newOIDCFixture(t, func(metadata *openIDConfiguration) {
							metadata.TokenEndpoint = endpoint.URL
						})
						cfg.IssuerURL = f.cfg.IssuerURL
						response.IDToken = signIDToken(t, f.claims(), f.key, "first", jwt.SigningMethodRS256)
					}
					client, err := NewClient(cfg, httpClient)
					if err != nil {
						t.Fatal(err)
					}
					handler, err := NewOAuthHandler(cfg, client)
					if err != nil {
						t.Fatal(err)
					}
					login := httptest.NewRecorder()
					handler.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
					location, err := url.Parse(login.Header().Get("Location"))
					if err != nil {
						t.Fatal(err)
					}
					challenge = location.Query().Get("code_challenge")
					if challenge == "" || location.Query().Get("code_challenge_method") != "S256" || location.Query().Has("code_verifier") {
						t.Fatal("authorization request must send only the S256 challenge")
					}
					second := httptest.NewRecorder()
					handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
					secondURL, err := url.Parse(second.Header().Get("Location"))
					if err != nil {
						t.Fatal(err)
					}
					if secondURL.Query().Get("code_challenge") == challenge || secondURL.Query().Get("state") == location.Query().Get("state") {
						t.Fatal("each login must generate fresh state and verifier")
					}
					// A different handler represents another stateless replica.
					callback, err := NewOAuthHandler(cfg, client)
					if err != nil {
						t.Fatal(err)
					}
					req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state="+location.Query().Get("state"), nil)
					req.AddCookie(login.Result().Cookies()[0])
					res := httptest.NewRecorder()
					callback.ServeHTTP(res, req)
					if !exchanged || res.Code != http.StatusSeeOther {
						t.Fatalf("PKCE callback failed: %d %s", res.Code, res.Body)
					}
					var sessionIssued, loginCleared bool
					for _, cookie := range res.Result().Cookies() {
						if cookie.Name == cfg.CookieName {
							sessionIssued = true
						}
						if cookie.Name == cfg.LoginCookie && cookie.MaxAge < 0 {
							loginCleared = true
						}
					}
					if !sessionIssued || !loginCleared {
						t.Fatal("callback must issue a session and clear the login cookie")
					}
				})
			}
		}
	}
}

func TestCallbackRejectsMissingPKCEVerifier(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	client := &errorRedirectClient{}
	handler, err := NewOAuthHandler(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	value, err := testCodec(t, cfg).Encode(cfg.LoginCookie, loginSession{State: "state"}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=state", nil)
	req.AddCookie(&http.Cookie{Name: cfg.LoginCookie, Value: value})
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || client.called {
		t.Fatal("missing verifier must fail before token exchange")
	}
}

func TestOAuthClientEndpointValidation(t *testing.T) {
	for _, allow := range []bool{false, true} {
		for _, endpoint := range []string{"authorization", "token"} {
			cfg := testConfig("https://provider.test/authorize", "https://provider.test/token")
			cfg.AllowHTTP = allow
			if endpoint == "authorization" {
				cfg.AuthorizationEndpoint.Scheme = "http"
			} else {
				cfg.TokenEndpoint.Scheme = "http"
			}
			if _, err := NewOAuthClient(cfg, nil); (err == nil) != allow {
				t.Fatalf("%s allow_http=%v: %v", endpoint, allow, err)
			}
		}
	}
}

func TestOAuthTokenHTTPRedirect(t *testing.T) {
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("code_verifier") != "verifier" {
			t.Error("redirect did not preserve verifier")
		}
		json.NewEncoder(w).Encode(Token{AccessToken: "token"})
	}))
	defer endpoint.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, endpoint.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	for _, allow := range []bool{false, true} {
		cfg := testConfig("https://provider.test/authorize", redirect.URL)
		cfg.AllowHTTP = allow
		client, err := NewOAuthClient(cfg, redirect.Client())
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Exchange(context.Background(), "code", "verifier")
		if (err == nil) != allow {
			t.Fatalf("allow_http=%v: %v", allow, err)
		}
		if !allow && requests.Load() != 0 {
			t.Fatal("sent credentials to HTTP redirect without opt-in")
		}
	}
	if requests.Load() != 1 {
		t.Fatal("opt-in did not permit HTTP redirect")
	}
	if redirect.Client().CheckRedirect != nil {
		t.Fatal("modified caller's HTTP client")
	}
}

func TestAllowHTTPKeepsTLSVerification(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("accepted an untrusted TLS certificate")
	}))
	defer endpoint.Close()
	cfg := testConfig("https://provider.test/authorize", endpoint.URL)
	cfg.AllowHTTP = true
	client, err := NewOAuthClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(context.Background(), "code", "verifier"); err == nil {
		t.Fatal("HTTP opt-in disabled TLS certificate verification")
	}
}
