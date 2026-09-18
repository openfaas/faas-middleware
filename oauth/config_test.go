package oauth

import (
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func setOAuthEnv(t *testing.T, values map[string]string) {
	t.Helper()
	keys := []string{
		"oauth_base_url",
		"oauth_session_default_ttl",
		"oauth_session_ttl",
		"oauth_issuer_url",
		"oauth_client_id",
		"oauth_client_secret",
		"oauth_authorization_endpoint",
		"oauth_token_endpoint",
		"oauth_token_auth_method",
		"oauth_scopes",
		"oauth_cookie_name",
		"oauth_signing_key",
		"oauth_login_cookie_name",
		"oauth_login_redirect",
		"oauth_logout_redirect",
		"oauth_error_redirect",
	}
	for _, k := range keys {
		value := values[k]
		if k == "oauth_signing_key" {
			if _, present := values[k]; !present {
				value = "cookie-secret"
			}
		}
		t.Setenv(k, value)
	}
}

func TestReadConfigDefaults(t *testing.T) {
	setOAuthEnv(t, map[string]string{
		"oauth_base_url":               "https://gateway.example.com/function/my-fn",
		"oauth_client_id":              "my-fn",
		"oauth_client_secret":          "secret",
		"oauth_authorization_endpoint": "https://issuer.example.com/authorize",
		"oauth_token_endpoint":         "https://issuer.example.com/token",
	})
	cfg, err := ReadConfig(testReadSecret)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientSecret != "file-client-secret" {
		t.Fatal("client secret was not loaded from the mounted file")
	}
	if !reflect.DeepEqual(cfg.Scopes, []string{"openid"}) {
		t.Fatalf("unexpected default scopes: %v", cfg.Scopes)
	}
	if cfg.CookieName != "of_session" || cfg.LoginCookie != "of_login" {
		t.Fatalf("unexpected default cookie names: %s / %s", cfg.CookieName, cfg.LoginCookie)
	}
	if cfg.redirectURL() != "https://gateway.example.com/function/my-fn/auth/callback" {
		t.Fatalf("unexpected redirect URL: %s", cfg.redirectURL())
	}
}

func TestReadConfigOverrides(t *testing.T) {
	setOAuthEnv(t, map[string]string{
		"oauth_base_url":               "https://gateway.example.com/function/my-fn",
		"oauth_client_id":              "my-fn",
		"oauth_client_secret":          "secret",
		"oauth_authorization_endpoint": "https://issuer.example.com/authorize",
		"oauth_token_endpoint":         "https://issuer.example.com/token",
		"oauth_scopes":                 "openid profile email",
		"oauth_cookie_name":            "app_session",
		"oauth_login_cookie_name":      "app_login",
		"oauth_login_redirect":         "https://gateway.example.com/function/my-fn/dashboard",
		"oauth_error_redirect":         "https://gateway.example.com/function/my-fn/login-error",
	})
	cfg, err := ReadConfig(testReadSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Scopes, []string{"openid", "profile", "email"}) {
		t.Fatalf("unexpected scopes: %v", cfg.Scopes)
	}
	if cfg.CookieName != "app_session" || cfg.LoginCookie != "app_login" {
		t.Fatalf("unexpected cookie names: %s / %s", cfg.CookieName, cfg.LoginCookie)
	}
	if cfg.ErrorRedirect != "https://gateway.example.com/function/my-fn/login-error" {
		t.Fatal("error redirect not configured")
	}
	if cfg.LoginRedirect != "https://gateway.example.com/function/my-fn/dashboard" {
		t.Fatalf("unexpected login redirect: %s", cfg.LoginRedirect)
	}
}

func TestReadConfigReadsSecretFromFile(t *testing.T) {
	setOAuthEnv(t, map[string]string{
		"oauth_base_url":               "https://gateway.example.com/function/my-fn",
		"oauth_client_id":              "my-fn",
		"oauth_client_secret":          "oauth-client-secret",
		"oauth_signing_key":            "oauth-cookie-secret",
		"oauth_authorization_endpoint": "https://issuer.example.com/authorize",
		"oauth_token_endpoint":         "https://issuer.example.com/token",
	})
	cfg, err := ReadConfig(func(path string) ([]byte, error) {
		if path == "/var/openfaas/secrets/oauth-cookie-secret" {
			return []byte(base64.StdEncoding.EncodeToString(testCookieSecret) + "\n"), nil
		}
		if path != "/var/openfaas/secrets/oauth-client-secret" {
			return nil, errors.New("unexpected path")
		}
		return []byte("file-secret\n"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientSecret != "file-secret" {
		t.Fatalf("unexpected client secret: %q", cfg.ClientSecret)
	}
}

func TestReadConfigRejectsInvalid(t *testing.T) {
	cases := []struct {
		name   string
		values map[string]string
	}{
		{
			"missing endpoints",
			map[string]string{
				"oauth_base_url":      "https://example.com",
				"oauth_client_id":     "id",
				"oauth_client_secret": "secret",
			},
		},
		{
			"missing client ID",
			map[string]string{
				"oauth_base_url":               "https://example.com",
				"oauth_authorization_endpoint": "https://x/authorize",
				"oauth_token_endpoint":         "https://x/token",
			},
		},
		{
			"bad endpoint",
			map[string]string{
				"oauth_base_url":               "https://example.com",
				"oauth_client_id":              "id",
				"oauth_client_secret":          "secret",
				"oauth_authorization_endpoint": "not-a-url",
				"oauth_token_endpoint":         "https://x/token",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setOAuthEnv(t, tc.values)
			if _, err := ReadConfig(testReadSecret); err == nil {
				t.Fatal("expected error, got none")
			}
		})
	}
}

func TestReadConfigOIDC(t *testing.T) {
	for _, issuer := range []string{"https://issuer.example.com", "https://issuer.example.com/tenant"} {
		t.Run(issuer, func(t *testing.T) {
			setOAuthEnv(t, map[string]string{
				"oauth_base_url":      "https://example.com/function/my-fn",
				"oauth_client_id":     "my-fn",
				"oauth_client_secret": "secret",
				"oauth_issuer_url":    issuer,
			})
			cfg, err := ReadConfig(testReadSecret)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.IssuerURL != issuer {
				t.Fatal("issuer URL not preserved")
			}
		})
	}
	for _, issuer := range []string{"not-a-url", "http://issuer.example.com", "https://user:password@issuer.example.com", "https://issuer.example.com#fragment", "https://issuer.example.com?query=value"} {
		t.Run(issuer, func(t *testing.T) {
			setOAuthEnv(t, map[string]string{
				"oauth_base_url":      "https://example.com/function/my-fn",
				"oauth_client_id":     "my-fn",
				"oauth_client_secret": "secret",
				"oauth_issuer_url":    issuer,
			})
			if _, err := ReadConfig(testReadSecret); err == nil {
				t.Fatal("accepted invalid issuer URL")
			}
		})
	}
}

func TestCookieSecretConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, path, contents string
		readError            error
		valid                bool
	}{
		{name: "missing path"},
		{name: "missing file", path: "cookie", readError: os.ErrNotExist},
		{name: "invalid base64", path: "cookie", contents: "not base64"},
		{name: "wrong size", path: "cookie", contents: base64.StdEncoding.EncodeToString([]byte("short"))},
		{name: "valid", path: "cookie", contents: base64.StdEncoding.EncodeToString(testCookieSecret) + "\n", valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setOAuthEnv(t, map[string]string{
				"oauth_base_url":  "https://example.com/function/my-fn",
				"oauth_client_id": "my-fn", "oauth_client_secret": "secret",
				"oauth_issuer_url":  "https://issuer.example.com",
				"oauth_signing_key": tc.path,
			})
			cfg, err := ReadConfig(func(path string) ([]byte, error) { return []byte(tc.contents), tc.readError })
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(cfg.CookieSecret, testCookieSecret) {
					t.Fatal("wrong cookie key loaded")
				}
			} else if err == nil {
				t.Fatal("accepted invalid cookie secret configuration")
			}
		})
	}
}

func testReadSecret(path string) ([]byte, error) {
	switch path {
	case "/var/openfaas/secrets/cookie-secret":
		return []byte(base64.StdEncoding.EncodeToString(testCookieSecret)), nil
	case "/var/openfaas/secrets/secret":
		return []byte("file-client-secret"), nil
	default:
		return nil, os.ErrNotExist
	}
}

func TestSecretFilenamesOnly(t *testing.T) {
	for _, env := range []string{"oauth_client_secret", "oauth_signing_key"} {
		for _, name := range []string{"", "/tmp/secret", "../secret", "nested/secret", ".", "..", `nested\secret`} {
			t.Run(env+"/"+name, func(t *testing.T) {
				t.Setenv(env, name)
				_, err := readSecret(env, func(string) ([]byte, error) { t.Fatal("invalid name reached file reader"); return nil, nil })
				if err == nil {
					t.Fatal("accepted invalid secret filename")
				}
			})
		}
	}
}

func TestClientSecretDoesNotFallBackToEnvironmentValue(t *testing.T) {
	setOAuthEnv(t, map[string]string{
		"oauth_base_url": "https://example.com", "oauth_client_id": "client",
		"oauth_client_secret": "inline-secret", "oauth_issuer_url": "https://issuer.example.com",
	})
	if _, err := ReadConfig(testReadSecret); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing secret file error, got %v", err)
	}
}

func TestLegacySecretVariablesAreIgnored(t *testing.T) {
	setOAuthEnv(t, map[string]string{
		"oauth_base_url": "https://example.com", "oauth_client_id": "client",
		"oauth_issuer_url": "https://issuer.example.com",
	})
	t.Setenv("oauth_client_secret_file", "/var/openfaas/secrets/secret")
	t.Setenv("oauth_cookie_secret_file", "/var/openfaas/secrets/cookie-secret")
	if cfg, err := ReadConfig(testReadSecret); err != nil || cfg.ClientSecret != "" {
		t.Fatalf("legacy client secret variable must be ignored: %v", err)
	}
	t.Setenv("oauth_client_secret", "secret")
	t.Setenv("oauth_signing_key", "")
	if _, err := ReadConfig(testReadSecret); err == nil {
		t.Fatal("accepted legacy cookie secret configuration")
	}
}

func TestSessionLifetimeConfig(t *testing.T) {
	for _, tc := range []struct {
		name, fallback, override  string
		wantDefault, wantOverride time.Duration
		invalid                   bool
	}{
		{name: "defaults", wantDefault: time.Hour},
		{name: "configured", fallback: "30m", override: "8h", wantDefault: 30 * time.Minute, wantOverride: 8 * time.Hour},
		{name: "invalid default", fallback: "invalid", invalid: true},
		{name: "zero", fallback: "0s", invalid: true},
		{name: "negative override", override: "-1h", invalid: true},
		{name: "fractional seconds", override: "1500ms", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setOAuthEnv(t, map[string]string{"oauth_base_url": "https://example.com", "oauth_client_id": "client", "oauth_client_secret": "secret", "oauth_issuer_url": "https://issuer.example.com", "oauth_session_default_ttl": tc.fallback, "oauth_session_ttl": tc.override})
			cfg, err := ReadConfig(testReadSecret)
			if tc.invalid {
				if err == nil {
					t.Fatal("accepted invalid lifetime")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.SessionDefaultTTL != tc.wantDefault || cfg.SessionTTL != tc.wantOverride {
				t.Fatal("incorrect lifetime configuration")
			}
		})
	}
}

func TestOptionalClientSecret(t *testing.T) {
	for _, issuer := range []string{"", "https://issuer.example"} {
		setOAuthEnv(t, map[string]string{
			"oauth_base_url": "https://example.com", "oauth_client_id": "client",
			"oauth_issuer_url":             issuer,
			"oauth_authorization_endpoint": "https://issuer.example/authorize",
			"oauth_token_endpoint":         "https://issuer.example/token",
		})
		cfg, err := ReadConfig(testReadSecret)
		if err != nil || cfg.ClientSecret != "" {
			t.Fatalf("public client configuration failed: %v", err)
		}
		t.Setenv("oauth_client_secret", "empty-secret")
		_, err = ReadConfig(func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "/empty-secret") {
				return []byte(" \n"), nil
			}
			return testReadSecret(path)
		})
		if err == nil {
			t.Fatal("configured but empty secret must not select public client mode")
		}
	}
}

func TestCookieNameValidation(t *testing.T) {
	for _, env := range []string{"oauth_cookie_name", "oauth_login_cookie_name"} {
		for _, name := range []string{"bad cookie", "bad;cookie", "bad=cookie", "bad\tcookie", "bad\ncookie", "café", "app_session-v2"} {
			t.Run(env+"/"+name, func(t *testing.T) {
				setOAuthEnv(t, map[string]string{
					"oauth_base_url": "https://example.com", "oauth_client_id": "client",
					"oauth_issuer_url": "https://issuer.example.com",
					env:                name,
				})
				valid := name == "app_session-v2"
				_, err := ReadConfig(testReadSecret)
				if valid && err != nil {
					t.Fatal(err)
				}
				if !valid && (err == nil || !strings.Contains(err.Error(), env)) {
					t.Fatalf("expected error identifying %s, got %v", env, err)
				}

				// Callers constructing Config directly must receive the same validation.
				cfg := testConfig("https://issuer.example/authorize", "https://issuer.example/token")
				if env == "oauth_cookie_name" {
					cfg.CookieName = name
				} else {
					cfg.LoginCookie = name
				}
				_, err = NewOAuthHandler(cfg, nil)
				if valid && err != nil {
					t.Fatal(err)
				}
				if !valid && (err == nil || !strings.Contains(err.Error(), env)) {
					t.Fatalf("expected constructor error identifying %s, got %v", env, err)
				}
			})
		}
	}
}
