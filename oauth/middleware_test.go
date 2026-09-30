package oauth

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestOAuthMiddlewarePreservesRequest(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	cfg.CookieName = "custom_session"
	signed, err := testCodec(t, cfg).Encode(cfg.CookieName, Session{Subject: "alice"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/private?query=value", strings.NewReader("body"))
	req.Header.Add("Cookie", "theme=dark; custom_session="+signed)
	req.Header.Add("Cookie", "other=value; quoted=\"hello world\"")
	req.Header.Set("X-Test", "preserved")
	original := req.Header.Clone()
	var calls int
	handler, err := NewOAuthMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r != req {
			t.Error("request should pass through unchanged")
		}
		cookie, err := r.Cookie(cfg.CookieName)
		if err != nil {
			t.Error(err)
			return
		}
		if cookie.Value != signed || !reflect.DeepEqual(r.Header, original) {
			t.Error("upstream did not receive the original signed cookie and headers")
		}
		for name, value := range map[string]string{"theme": "dark", "other": "value", "quoted": "hello world"} {
			c, err := r.Cookie(name)
			if err != nil || c.Value != value {
				t.Errorf("unrelated cookie %s changed", name)
			}
		}
		if r.Header.Get("X-Test") != "preserved" || r.URL.String() != req.URL.String() || r.Method != req.Method || r.Body != req.Body {
			t.Error("request changed beyond cookie headers")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	if err != nil {
		t.Fatal(err)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if calls != 1 || res.Code != http.StatusAccepted {
		t.Fatal("request did not reach upstream")
	}
	if !reflect.DeepEqual(req.Header, original) {
		t.Fatal("original request headers changed")
	}
	if len(res.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("rewrote browser cookie")
	}
}

func TestOAuthMiddlewareRejectsInvalidSessions(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	codec := testCodec(t, cfg)
	valid, err := codec.Encode(cfg.CookieName, Session{Subject: "alice"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	wrongName, err := codec.Encode(cfg.LoginCookie, "state", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	expiredClaims := validCookieClaims(t, codec, cfg.CookieName)
	expiredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Second))
	expired := signCookieClaims(t, codec, expiredClaims, jwt.SigningMethodHS256, codec.signingKey)
	plaintext := "eyJhY2Nlc3NfdG9rZW4iOiJ1bnRydXN0ZWQifQ"
	for name, headers := range map[string][]string{
		"plaintext":                 {"of_session=" + plaintext},
		"tampered":                  {"of_session=" + valid[:len(valid)-2] + "AA"},
		"empty":                     {"of_session="},
		"expired":                   {"of_session=" + expired},
		"login cookie substitution": {"of_session=" + wrongName},
		"duplicate":                 {"of_session=" + valid + "; of_session=" + valid},
		"duplicate headers":         {"of_session=" + valid, "of_session=" + valid},
		"malformed":                 {"of_session=\"unterminated"},
		"missing equals":            {"of_session"},
		"malformed duplicate":       {"of_session=" + valid, "of_session=\"unterminated"},
		"oversized":                 {"of_session=" + strings.Repeat("x", maxCookieValueBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			handler, err := NewOAuthMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("invalid session reached upstream") }))
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header["Cookie"] = headers
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusSeeOther {
				t.Fatalf("status %d, expected 303", res.Code)
			}
			if location := res.Header().Get("Location"); location != loginURL(cfg) {
				t.Fatalf("redirect to %q, expected login page %q", location, loginURL(cfg))
			}
			if res.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("rejection must not be cached")
			}
		})
	}
}

func TestOAuthMiddlewareRedirectsAnonymousRequests(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	for _, header := range []string{"", "theme=dark"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			req.Header.Set("Cookie", header)
		}
		handler, err := NewOAuthMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("anonymous request must not reach upstream")
		}))
		if err != nil {
			t.Fatal(err)
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusSeeOther {
			t.Fatalf("anonymous request returned %d, expected 303", res.Code)
		}
		if location := res.Header().Get("Location"); location != loginURL(cfg) {
			t.Fatalf("redirect to %q, expected login page %q", location, loginURL(cfg))
		}
		if res.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("redirect must not be cached")
		}
	}
}

func loginURL(cfg Config) string {
	return cfg.BaseURL.JoinPath("/auth/login").String()
}

func TestOAuthMiddlewareDuplicateCookieScopes(t *testing.T) {
	for _, tc := range []struct {
		base  string
		paths []string
	}{
		{"https://example.com", []string{"/"}},
		{"https://example.com/", []string{"/"}},
		{"http://example.com/function/my-fn/", []string{"/", "/function/my-fn"}},
		{"https://example.com/function/my%20fn/", []string{"/", "/function/my%20fn"}},
	} {
		t.Run(tc.base, func(t *testing.T) {
			cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
			cfg.BaseURL, _ = url.Parse(tc.base)
			cfg.CookieName = "custom_session"
			handler, err := NewOAuthMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("duplicate cookies reached the application")
			}))
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, tc.base, nil)
			req.Header.Set("Cookie", "custom_session=one; custom_session=two")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			var paths []string
			for _, cookie := range res.Result().Cookies() {
				paths = append(paths, cookie.Path)
				if cookie.Name != cfg.CookieName || cookie.Value != "" || cookie.MaxAge != -1 ||
					cookie.Domain != "" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode ||
					cookie.Secure != (cfg.BaseURL.Scheme == "https") {
					t.Fatalf("unexpected expired cookie: %+v", cookie)
				}
			}
			if !reflect.DeepEqual(paths, tc.paths) {
				t.Fatalf("expired cookie paths %v, want %v", paths, tc.paths)
			}
		})
	}
}

func TestOAuthMiddlewareRecoversFromDuplicateSessionCookies(t *testing.T) {
	for _, suffix := range []string{"", "/"} {
		t.Run("base URL suffix="+suffix, func(t *testing.T) {
			cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
			cfg.BaseURL.Path += suffix
			prefix := strings.TrimRight(cfg.BaseURL.Path, "/")
			client := &stubClient{token: Token{IDToken: fakeJWT(map[string]any{"sub": "new-session", "exp": time.Now().Add(time.Hour).Unix()})}}
			authHandler, err := NewOAuthHandler(cfg, client)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			protected, err := NewOAuthMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(http.StatusNoContent)
			}))
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			mux.Handle("/auth/", authHandler)
			mux.Handle("/", protected)
			handler := http.StripPrefix(prefix, mux)
			jar, _ := cookiejar.New(nil)
			signed, err := testCodec(t, cfg).Encode(cfg.CookieName, Session{Subject: "old-session"}, time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(cfg.BaseURL, []*http.Cookie{
				{Name: cfg.CookieName, Value: "legacy-session", Path: "/", Secure: true},
				{Name: cfg.CookieName, Value: signed, Path: prefix, Secure: true},
				{Name: cfg.CookieName, Value: "other-function", Path: "/function/other", Secure: true},
				{Name: "theme", Value: "dark", Path: "/"},
			})
			request := func(method, target string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(method, target, nil)
				for _, cookie := range jar.Cookies(req.URL) {
					req.AddCookie(cookie)
				}
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, req)
				jar.SetCookies(req.URL, res.Result().Cookies())
				return res
			}

			initial := request(http.MethodGet, cfg.BaseURL.JoinPath("private").String())
			if initial.Code != http.StatusSeeOther || initial.Header().Get("Location") != loginURL(cfg) || calls != 0 {
				t.Fatal("duplicate cookies must redirect to login without reaching the application")
			}
			if page := request(http.MethodGet, initial.Header().Get("Location")); page.Code != http.StatusOK {
				t.Fatalf("login page returned %d", page.Code)
			}
			login := request(http.MethodPost, loginURL(cfg))
			if login.Code != http.StatusFound {
				t.Fatalf("login returned %d", login.Code)
			}
			var state loginSession
			if err := testCodec(t, cfg).Decode(cfg.LoginCookie, login.Result().Cookies()[0].Value, &state); err != nil {
				t.Fatal(err)
			}
			callbackURL := cfg.BaseURL.JoinPath("auth/callback")
			callbackURL.RawQuery = url.Values{"code": {"code"}, "state": {state.State}}.Encode()
			callback := request(http.MethodGet, callbackURL.String())
			if callback.Code != http.StatusSeeOther || callback.Header().Get("Location") != cfg.BaseURL.String() || !client.called {
				t.Fatalf("callback did not complete sign-in: status %d", callback.Code)
			}
			if res := request(http.MethodGet, cfg.BaseURL.JoinPath("private").String()); res.Code != http.StatusNoContent || calls != 1 {
				t.Fatalf("successful sign-in left the browser in a login loop: status %d, application calls %d", res.Code, calls)
			}
			cookies := jar.Cookies(cfg.BaseURL)
			if len(cookies) != 2 {
				t.Fatalf("expected one session cookie and the theme cookie, got %d cookies", len(cookies))
			}
			for _, cookie := range cookies {
				switch cookie.Name {
				case cfg.CookieName:
					var session Session
					if err := testCodec(t, cfg).Decode(cfg.CookieName, cookie.Value, &session); err != nil || session.Subject != "fed:new-session" {
						t.Fatal("browser did not retain the new session")
					}
				case "theme":
					if cookie.Value != "dark" {
						t.Fatal("unrelated cookie changed")
					}
				}
			}
			otherURL, _ := url.Parse("https://example.com/function/other")
			for _, cookie := range jar.Cookies(otherURL) {
				if cookie.Name == cfg.CookieName && cookie.Value == "other-function" {
					return
				}
			}
			t.Fatal("another function's session cookie was removed")
		})
	}
}

func TestOIDCSessionThroughHTTPProxy(t *testing.T) {
	f := newOIDCFixture(t, nil)
	raw := signIDToken(t, f.claims(), f.key, "first", jwt.SigningMethodRS256)
	f.token.Store(map[string]string{"id_token": raw, "access_token": "opaque"})
	authHandler, err := NewOAuthHandler(f.cfg, f.client(t))
	if err != nil {
		t.Fatal(err)
	}
	var session string
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		cookie, err := r.Cookie(f.cfg.CookieName)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		var identity Session
		err = testCodec(t, f.cfg).Decode(f.cfg.CookieName, cookie.Value, &identity)
		if err != nil || identity != (Session{Subject: "fed:alice", FederatedIssuer: f.cfg.IssuerURL}) || cookie.Value != session || strings.Contains(cookie.Value, "opaque") {
			t.Error("proxy did not forward the original signed session JWT")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy, err := NewOAuthMiddleware(f.cfg, httputil.NewSingleHostReverseProxy(target))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/", authHandler)
	mux.Handle("/", proxy)
	prefix := strings.TrimRight(f.cfg.BaseURL.Path, "/")
	server := httptest.NewTLSServer(http.StripPrefix(prefix, mux))
	defer server.Close()
	browser := server.Client()
	browser.Jar, _ = cookiejar.New(nil)
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	login, err := browser.Post(server.URL+prefix+"/auth/login", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	location, err := url.Parse(login.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	callback, err := browser.Get(server.URL + prefix + "/auth/callback?code=code&state=" + location.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	callback.Body.Close()
	if callback.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback failed: %d", callback.StatusCode)
	}
	browserURL, _ := url.Parse(server.URL + prefix + "/")
	for _, cookie := range browser.Jar.Cookies(browserURL) {
		if cookie.Name == f.cfg.CookieName {
			session = cookie.Value
		}
	}
	if len(strings.Split(session, ".")) != 3 {
		t.Fatal("browser did not receive a signed JWT cookie")
	}
	// Preserve the session cookie for both ordinary and streaming requests.
	for _, accept := range []string{"application/json", "text/event-stream"} {
		req, _ := http.NewRequest(http.MethodGet, server.URL+prefix+"/", nil)
		req.Header.Set("Accept", accept)
		res, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("proxy returned %d", res.StatusCode)
		}
		if len(res.Cookies()) != 0 {
			t.Fatal("plaintext cookie sent to browser")
		}
	}
	if calls.Load() != 2 {
		t.Fatal("upstream did not receive both proxy requests")
	}
	for _, cookie := range browser.Jar.Cookies(browserURL) {
		if cookie.Name == f.cfg.CookieName && cookie.Value != session {
			t.Fatal("browser cookie replaced with plaintext")
		}
	}
	// The auth routes bypass the middleware so logout still works with bad cookies.
	browser.Jar.SetCookies(browserURL, []*http.Cookie{{Name: f.cfg.CookieName, Value: "tampered", Path: prefix}})
	logout, err := browser.Post(server.URL+prefix+"/auth/logout", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	logout.Body.Close()
	if logout.StatusCode != http.StatusSeeOther {
		t.Fatal("middleware blocked logout")
	}
	for _, cookie := range browser.Jar.Cookies(browserURL) {
		if cookie.Name == f.cfg.CookieName {
			t.Fatal("logout failed to remove session")
		}
	}
}
