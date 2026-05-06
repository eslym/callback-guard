package main

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestValidateProxyRequest(t *testing.T) {
	t.Run("valid connect", func(t *testing.T) {
		r := &http.Request{Method: http.MethodConnect, Host: "example.com:443"}
		if err := validateProxyRequest(r); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("invalid connect host", func(t *testing.T) {
		r := &http.Request{Method: http.MethodConnect, Host: "example.com"}
		if err := validateProxyRequest(r); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("unsupported scheme", func(t *testing.T) {
		u, _ := url.Parse("ftp://example.com/file")
		r := &http.Request{Method: http.MethodGet, URL: u}
		if err := validateProxyRequest(r); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("relative URL denied", func(t *testing.T) {
		u, _ := url.Parse("/local/path")
		r := &http.Request{Method: http.MethodGet, URL: u}
		if err := validateProxyRequest(r); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("userinfo denied", func(t *testing.T) {
		u, _ := url.Parse("http://user:pass@example.com/resource")
		r := &http.Request{Method: http.MethodGet, URL: u}
		if err := validateProxyRequest(r); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid destination port denied", func(t *testing.T) {
		u, _ := url.Parse("http://example.com:70000/resource")
		r := &http.Request{Method: http.MethodGet, URL: u}
		if err := validateProxyRequest(r); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestIsMetadataEndpoint(t *testing.T) {
	if !isMetadataEndpoint("metadata.google.internal", net.ParseIP("203.0.113.1")) {
		t.Fatal("expected metadata.google.internal to be blocked")
	}
	if !isMetadataEndpoint("anything", net.ParseIP("169.254.169.254")) {
		t.Fatal("expected 169.254.169.254 to be blocked")
	}
	if isMetadataEndpoint("example.com", net.ParseIP("203.0.113.10")) {
		t.Fatal("did not expect public endpoint to be blocked")
	}
}

func TestAuthLimiterBlocksAfterThreshold(t *testing.T) {
	al := newAuthLimiter(1*time.Minute, 2, 5*time.Minute)
	now := time.Now()
	key := "127.0.0.1|alice"
	al.recordFailure(key, now)
	if al.isBlocked(key, now) {
		t.Fatal("should not be blocked after first failure")
	}
	al.recordFailure(key, now)
	if !al.isBlocked(key, now.Add(1*time.Second)) {
		t.Fatal("expected blocked after threshold")
	}
}

func TestCheckAuthRateLimit(t *testing.T) {
	hash, err := bcryptPassword("secret")
	if err != nil {
		t.Fatalf("failed generating hash: %v", err)
	}
	p := &ProxyServer{
		authEnabled: true,
		authUsers: map[string][]byte{
			"alice": hash,
		},
		authLimiter: newAuthLimiter(1*time.Minute, 2, 5*time.Minute),
	}

	bad := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong"))
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Proxy-Authorization", bad)
		w := httptest.NewRecorder()
		ok, _ := p.checkAuth(w, r)
		if ok {
			t.Fatal("expected auth failure")
		}
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Proxy-Authorization", bad)
	w := httptest.NewRecorder()
	ok, _ := p.checkAuth(w, r)
	if ok {
		t.Fatal("expected blocked auth")
	}
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %d", w.Code)
	}
}

func bcryptPassword(pass string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
}

func TestValidateSecurityConfig(t *testing.T) {
	t.Run("invalid allowed port", func(t *testing.T) {
		err := validateSecurityConfig(SecurityConfig{AllowedPorts: []int{443, 70000}})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid auth settings", func(t *testing.T) {
		err := validateSecurityConfig(SecurityConfig{
			AuthRateLimit:   true,
			AuthMaxFailures: 0,
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid connect lifetime", func(t *testing.T) {
		err := validateSecurityConfig(SecurityConfig{ConnectMaxLifetime: "-5s"})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("valid config", func(t *testing.T) {
		err := validateSecurityConfig(SecurityConfig{
			AllowedPorts:       []int{80, 443},
			AuthRateLimit:      true,
			AuthMaxFailures:    5,
			AuthWindow:         "30s",
			AuthBlockDuration:  "2m",
			ConnectMaxLifetime: "10m",
		})
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
}

func TestAuthLimiterPrunesEntries(t *testing.T) {
	al := newAuthLimiter(1*time.Minute, 3, 5*time.Minute)
	al.pruneInterval = time.Nanosecond
	now := time.Now()
	key := "127.0.0.1|bob"
	al.recordFailure(key, now.Add(-2*time.Minute))
	al.isBlocked("nope", now)

	al.mu.Lock()
	_, ok := al.entries[key]
	al.mu.Unlock()
	if ok {
		t.Fatal("expected stale entry to be pruned")
	}
}
