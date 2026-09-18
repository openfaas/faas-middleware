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
	token := Token{IDToken: "id-token", AccessToken: "access-token"}
	signed, err := testCodec(t, cfg).Encode(cfg.CookieName, token, time.Now().Add(time.Hour))
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
	valid, err := codec.Encode(cfg.CookieName, Token{AccessToken: "token"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	wrongName, err := codec.Encode(cfg.LoginCookie, "state", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	empty, err := codec.Encode(cfg.CookieName, Token{}, time.Now().Add(time.Hour))
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
		"empty token":               {"of_session=" + empty},
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
			if res.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, expected 401", res.Code)
			}
			if res.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("rejection must not be cached")
			}
		})
	}
}

func TestOAuthMiddlewareAllowsAnonymousRequests(t *testing.T) {
	cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
	for _, header := range []string{"", "theme=dark"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			req.Header.Set("Cookie", header)
		}
		handler, err := NewOAuthMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r != req {
				t.Error("anonymous request should pass through unchanged")
			}
			w.WriteHeader(http.StatusOK)
		}))
		if err != nil {
			t.Fatal(err)
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("anonymous request returned %d", res.Code)
		}
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
		var token Token
		err = testCodec(t, f.cfg).Decode(f.cfg.CookieName, cookie.Value, &token)
		if err != nil || token.IDToken != raw || token.AccessToken != "opaque" || cookie.Value != session {
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
	login, err := browser.Get(server.URL + prefix + "/auth/login")
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
