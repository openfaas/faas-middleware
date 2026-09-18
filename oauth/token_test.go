package oauth

import (
	"testing"
	"time"
)

func TestSessionExpiry(t *testing.T) {
	now := time.Unix(1800000000, 0)
	id := fakeJWT(map[string]any{"sub": "alice", "exp": now.Add(2 * time.Hour).Unix()})
	for _, tc := range []struct {
		name                     string
		token                    Token
		fallback, override, want time.Duration
		invalid                  bool
	}{
		{name: "OIDC", token: Token{IDToken: id, ExpiresIn: 60}, want: 2 * time.Hour},
		{name: "opaque OAuth", token: Token{AccessToken: "opaque", ExpiresIn: 120}, want: 2 * time.Minute},
		{name: "long OAuth lifetime", token: Token{AccessToken: "opaque", ExpiresIn: 7200}, want: 2 * time.Hour},
		{name: "OAuth JWT uses response lifetime", token: Token{AccessToken: id, ExpiresIn: 120}, want: 2 * time.Minute},
		{name: "default", token: Token{AccessToken: "opaque"}, want: time.Hour},
		{name: "configured default", token: Token{AccessToken: "opaque"}, fallback: 15 * time.Minute, want: 15 * time.Minute},
		{name: "OIDC longer override", token: Token{IDToken: id}, override: 8 * time.Hour, want: 8 * time.Hour},
		{name: "OIDC shorter override", token: Token{IDToken: id}, override: time.Minute, want: time.Minute},
		{name: "OAuth override", token: Token{AccessToken: "opaque", ExpiresIn: 60}, override: 8 * time.Hour, want: 8 * time.Hour},
		{name: "override default", token: Token{AccessToken: "opaque"}, override: 8 * time.Hour, want: 8 * time.Hour},
		{name: "expired ID despite override", token: Token{IDToken: fakeJWT(map[string]any{"sub": "alice", "exp": now.Add(-time.Hour).Unix()})}, override: time.Hour, invalid: true},
		{name: "missing ID expiry", token: Token{IDToken: fakeJWT(map[string]any{"sub": "alice"})}, invalid: true},
		{name: "negative lifetime", token: Token{AccessToken: "opaque", ExpiresIn: -1}, invalid: true},
		{name: "overflow", token: Token{AccessToken: "opaque", ExpiresIn: 1<<63 - 1}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &OAuthHandler{sessionDefaultTTL: time.Hour, sessionTTL: tc.override}
			if tc.fallback != 0 {
				h.sessionDefaultTTL = tc.fallback
			}
			expires, err := h.sessionExpiry(tc.token, now)
			if tc.invalid {
				if err == nil {
					t.Fatal("accepted invalid expiry")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !expires.Equal(now.Add(tc.want)) {
				t.Fatalf("expiry %s, want %s", expires, now.Add(tc.want))
			}
		})
	}
}
