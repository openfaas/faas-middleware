package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rakutentech/jwk-go/jwk"
)

func Test_isAuthorized(t *testing.T) {
	tests := []struct {
		name        string
		want        bool
		permissions AuthPermissions
		namespace   string
		function    string
	}{
		{
			name: "deny empty permission list",
			want: false,
			permissions: AuthPermissions{
				Permissions: []string{},
			},
			namespace: "staging",
			function:  "env",
		},
		{
			name: "allow empty audience list",
			want: true,
			permissions: AuthPermissions{
				Permissions: []string{"staging:env"},
			},
			namespace: "staging",
			function:  "env",
		},
		{
			name: "allow cluster wildcard",
			want: true,
			permissions: AuthPermissions{
				Permissions: []string{"*"},
			},
			namespace: "staging",
			function:  "figlet",
		},
		{
			name: "allow function wildcard",
			want: true,
			permissions: AuthPermissions{
				Permissions: []string{"dev:*"},
			},
			namespace: "dev",
			function:  "figlet",
		},
		{
			name: "allow namespace wildcard",
			want: true,
			permissions: AuthPermissions{
				Permissions: []string{"*:env"},
			},
			namespace: "openfaas-fn",
			function:  "env",
		},
		{
			name: "allow function",
			want: true,
			permissions: AuthPermissions{
				Permissions: []string{"openfaas-fn:env"},
			},
			namespace: "openfaas-fn",
			function:  "env",
		},
		{
			name: "deny function",
			want: false,
			permissions: AuthPermissions{
				Permissions: []string{"openfaas-fn:env"},
			},
			namespace: "openfaas-fn",
			function:  "figlet",
		},
		{
			name: "deny namespace",
			want: false,
			permissions: AuthPermissions{
				Permissions: []string{"openfaas-fn:*"},
			},
			namespace: "staging",
			function:  "env",
		},
		{
			name: "deny namespace wildcard",
			want: false,
			permissions: AuthPermissions{
				Permissions: []string{"*:figlet"},
			},
			namespace: "staging",
			function:  "env",
		},
		{
			name: "multiple permissions allow function",
			want: true,
			permissions: AuthPermissions{
				Permissions: []string{"openfaas-fn:*", "staging:env"},
			},
			namespace: "staging",
			function:  "env",
		},
		{
			name: "multiple permissions deny function",
			want: false,
			permissions: AuthPermissions{
				Permissions: []string{"openfaas-fn:figlet", "staging-*:env"},
			},
			namespace: "staging",
			function:  "env",
		},
		{
			name: "allow audience",
			want: true,
			permissions: AuthPermissions{
				Permissions: []string{"openfaas-fn:*"},
				Audience:    []string{"openfaas-fn:env"},
			},
			namespace: "openfaas-fn",
			function:  "env",
		},
		{
			name: "deny audience",
			want: false,
			permissions: AuthPermissions{
				Permissions: []string{"openfaas-fn:*"},
				Audience:    []string{"openfaas-fn:env"},
			},
			namespace: "openfaas-fn",
			function:  "figlet",
		},
		{
			name: "allow audience function wildcard",
			want: true,
			permissions: AuthPermissions{
				Permissions: []string{"openfaas-fn:figlet"},
				Audience:    []string{"openfaas-fn:*"},
			},
			namespace: "openfaas-fn",
			function:  "figlet",
		},
		{
			name: "deny audience function wildcard",
			want: false,
			permissions: AuthPermissions{
				Permissions: []string{"openfaas-fn:figlet", "dev:env"},
				Audience:    []string{"openfaas-fn:*"},
			},
			namespace: "dev",
			function:  "env",
		},
		{
			name: "deny audience namespace wildcard",
			want: false,
			permissions: AuthPermissions{
				Permissions: []string{"openfaas-fn:*", "dev:*"},
				Audience:    []string{"*:env"},
			},
			namespace: "dev",
			function:  "figlet",
		},
		{
			name: "allow audience namespace wildcard",
			want: true,
			permissions: AuthPermissions{
				Permissions: []string{"openfaas-fn:*", "dev:*"},
				Audience:    []string{"*:env"},
			},
			namespace: "openfaas-fn",
			function:  "env",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := test.want
			got := isAuthorized(test.permissions, test.namespace, test.function)

			if want != got {
				t.Errorf("want: %t, got: %t", want, got)
			}
		})
	}
}

func TestMatchString(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{name: "exact match", pattern: "default:foo", value: "default:foo", want: true},
		{name: "suffix must not match", pattern: "default:foo", value: "default:foobar", want: false},
		{name: "prefix must not match", pattern: "default:foo", value: "xdefault:foo", want: false},
		{name: "embedded must not match", pattern: "default:foo", value: "xdefault:fooy", want: false},
		{name: "wildcard suffix", pattern: "default:foo*", value: "default:foobar", want: true},
		{name: "wildcard prefix", pattern: "*foo", value: "xfoo", want: true},
		{name: "wildcard middle", pattern: "ns:*fn", value: "ns:myfn", want: true},
		{name: "empty pattern", pattern: "", value: "default:foo", want: false},
		{name: "regex meta is quoted", pattern: "ns:fn(x", value: "ns:fn(x", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchString(tc.pattern, tc.value); got != tc.want {
				t.Fatalf("matchString(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
			}
		})
	}
}

func TestValidateKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		method jwt.SigningMethod
		key    interface{}
		want   bool
	}{
		{name: "RS256 with RSA key", method: jwt.SigningMethodRS256, key: &rsaKey.PublicKey, want: true},
		{name: "PS256 with RSA key", method: jwt.SigningMethodPS256, key: &rsaKey.PublicKey, want: true},
		{name: "ES256 with EC key", method: jwt.SigningMethodES256, key: &ecKey.PublicKey, want: true},
		{name: "HS256 with RSA key", method: jwt.SigningMethodHS256, key: &rsaKey.PublicKey, want: false},
		{name: "ES256 with RSA key", method: jwt.SigningMethodES256, key: &rsaKey.PublicKey, want: false},
		{name: "RS256 with EC key", method: jwt.SigningMethodRS256, key: &ecKey.PublicKey, want: false},
		{name: "HS256 with symmetric key", method: jwt.SigningMethodHS256, key: []byte("secret"), want: false},
		{name: "RS256 with symmetric key", method: jwt.SigningMethodRS256, key: []byte("secret"), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := jwk.KeySpec{Key: tc.key}
			err := validateKeyType(tc.method, &spec)
			if (err == nil) != tc.want {
				t.Fatalf("validateKeyType(%s, key) error = %v, want nil: %v", tc.method.Alg(), err, tc.want)
			}
		})
	}
}

const testIssuer = "https://gateway.openfaas.example"

func testFunctionClaims(permissions, audience []string) FunctionClaims {
	return FunctionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{testIssuer},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Authentication: AuthPermissions{
			Permissions: permissions,
			Audience:    audience,
		},
	}
}

func signToken(t *testing.T, key interface{}, method jwt.SigningMethod, kid string, claims jwt.Claims) string {
	t.Helper()

	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %s", err)
	}
	return signed
}

func newJWTAuthTestHandler(keySet jwk.KeySpecSet) (jwtAuth, *bool) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	return jwtAuth{
		next:   next,
		opts:   JWTAuthOptions{Name: "fn", Namespace: "ns"},
		keySet: keySet,
		issuer: testIssuer,
	}, &called
}

func doRequest(t *testing.T, h http.Handler, authorization string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestServeHTTPRS256Accepted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	keySet := jwk.KeySpecSet{Keys: []jwk.KeySpec{{Key: &key.PublicKey, KeyID: "test-key"}}}
	handler, called := newJWTAuthTestHandler(keySet)

	token := signToken(t, key, jwt.SigningMethodRS256, "test-key", testFunctionClaims([]string{"ns:fn"}, []string{"ns:fn"}))

	rec := doRequest(t, handler, "Bearer "+token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !*called {
		t.Fatal("next handler was not called")
	}
}

func TestServeHTTPLowercaseBearerScheme(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	keySet := jwk.KeySpecSet{Keys: []jwk.KeySpec{{Key: &key.PublicKey, KeyID: "test-key"}}}
	handler, called := newJWTAuthTestHandler(keySet)

	token := signToken(t, key, jwt.SigningMethodRS256, "test-key", testFunctionClaims([]string{"ns:fn"}, []string{"ns:fn"}))

	rec := doRequest(t, handler, "bearer "+token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !*called {
		t.Fatal("next handler was not called")
	}
}

func TestServeHTTPES256Accepted(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	keySet := jwk.KeySpecSet{Keys: []jwk.KeySpec{{Key: &key.PublicKey, KeyID: "test-key"}}}
	handler, called := newJWTAuthTestHandler(keySet)

	token := signToken(t, key, jwt.SigningMethodES256, "test-key", testFunctionClaims([]string{"ns:fn"}, []string{"ns:fn"}))

	rec := doRequest(t, handler, "Bearer "+token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !*called {
		t.Fatal("next handler was not called")
	}
}

func TestServeHTTPRejects(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	keySet := jwk.KeySpecSet{Keys: []jwk.KeySpec{{Key: &rsaKey.PublicKey, KeyID: "test-key"}}}
	handler, _ := newJWTAuthTestHandler(keySet)

	validClaims := testFunctionClaims([]string{"ns:fn"}, []string{"ns:fn"})

	cases := []struct {
		name          string
		authorization string
		want          int
	}{
		{
			name:          "no authorization header",
			authorization: "",
			want:          http.StatusUnauthorized,
		},
		{
			name:          "non-bearer scheme",
			authorization: "Basic dXNlcjpwYXNz",
			want:          http.StatusUnauthorized,
		},
		{
			name:          "HS256 algorithm confusion",
			authorization: "Bearer " + signToken(t, []byte("secret"), jwt.SigningMethodHS256, "test-key", validClaims),
			want:          http.StatusUnauthorized,
		},
		{
			name:          "none algorithm",
			authorization: "Bearer " + signToken(t, jwt.UnsafeAllowNoneSignatureType, jwt.SigningMethodNone, "test-key", validClaims),
			want:          http.StatusUnauthorized,
		},
		{
			name:          "unknown kid",
			authorization: "Bearer " + signToken(t, rsaKey, jwt.SigningMethodRS256, "other-key", validClaims),
			want:          http.StatusUnauthorized,
		},
		{
			name:          "alg does not match key type",
			authorization: "Bearer " + signToken(t, ecKey, jwt.SigningMethodES256, "test-key", validClaims),
			want:          http.StatusUnauthorized,
		},
		{
			name: "wrong issuer",
			authorization: "Bearer " + signToken(t, rsaKey, jwt.SigningMethodRS256, "test-key", func() jwt.Claims {
				claims := validClaims
				claims.Issuer = "https://evil.example"
				return claims
			}()),
			want: http.StatusUnauthorized,
		},
		{
			name: "expired token",
			authorization: "Bearer " + signToken(t, rsaKey, jwt.SigningMethodRS256, "test-key", func() jwt.Claims {
				claims := validClaims
				claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
				return claims
			}()),
			want: http.StatusUnauthorized,
		},
		{
			name:          "token for another function",
			authorization: "Bearer " + signToken(t, rsaKey, jwt.SigningMethodRS256, "test-key", testFunctionClaims([]string{"ns:other"}, []string{"ns:other"})),
			want:          http.StatusForbidden,
		},
		{
			name:          "token scoped to sibling prefix",
			authorization: "Bearer " + signToken(t, rsaKey, jwt.SigningMethodRS256, "test-key", testFunctionClaims([]string{"ns:fn2"}, []string{"ns:fn2"})),
			want:          http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(t, handler, tc.authorization)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}

			// The raw token must never be echoed back to the client.
			if tc.authorization != "" && strings.Contains(rec.Body.String(), tc.authorization) {
				t.Fatalf("response body echoes the Authorization header")
			}
		})
	}
}
