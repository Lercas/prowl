package safehttp

import (
	"net"
	"net/http"
	"net/url"
	"testing"
)

// TestSafeTransportNoProxyByDefault locks in the SSRF fix: the guarded transport must NOT use
// proxy-from-environment by default. If it did, a request to an attacker-chosen URL (e.g.
// http://169.254.169.254/) would be dialed to the proxy's IP and the dial-time guard — which only
// ever sees the dialed address — would vet the proxy, not the internal target, bypassing the guard.
func TestSafeTransportNoProxyByDefault(t *testing.T) {
	defer func() { AllowPrivate.Store(false) }()
	t.Setenv("HTTP_PROXY", "http://proxy.example:3128")
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")

	AllowPrivate.Store(false)
	tr := SafeTransport(0)
	if tr.Proxy != nil {
		// Even with a proxy env set, Proxy must be nil so every dial goes to the real target and the
		// Control guard inspects the target IP.
		req, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
		if u, err := tr.Proxy(req); err == nil && u != nil {
			t.Fatalf("default SafeTransport routed via proxy %v; SSRF guard would be bypassed", u)
		}
		t.Fatal("default SafeTransport must have a nil Proxy (no proxy-from-env)")
	}

	// Escape hatch: when the operator opts into internal space the guard is off by design, so a
	// corporate egress proxy is honoured again.
	AllowPrivate.Store(true)
	tr = SafeTransport(0)
	if tr.Proxy == nil {
		t.Fatal("with AllowPrivate set, proxy-from-env should be honoured")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	u, err := tr.Proxy(req)
	if err != nil || u == nil || u.Host != "proxy.example:3128" {
		t.Fatalf("AllowPrivate proxy = (%v, %v), want proxy.example:3128", u, err)
	}
}

func TestIsInternal(t *testing.T) {
	internal := []string{
		"127.0.0.1", "::1", "169.254.169.254", "10.0.0.5", "192.168.1.1",
		"172.16.0.1", "0.0.0.0", "0.1.2.3", "fe80::1", "fc00::1", "fd12::34",
	}
	for _, s := range internal {
		if ip := net.ParseIP(s); ip == nil || !isInternal(ip) {
			t.Errorf("isInternal(%q) = false, want true", s)
		}
	}
	external := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range external {
		if ip := net.ParseIP(s); ip == nil || isInternal(ip) {
			t.Errorf("isInternal(%q) = true, want false", s)
		}
	}
}

func TestBlockPrivateIPsControl(t *testing.T) {
	defer func() { AllowPrivate.Store(false) }()
	AllowPrivate.Store(false)
	if err := blockPrivateIPs("tcp", "169.254.169.254:80", nil); err == nil {
		t.Error("expected link-local metadata IP to be blocked")
	}
	if err := blockPrivateIPs("tcp", "10.1.2.3:443", nil); err == nil {
		t.Error("expected RFC1918 IP to be blocked")
	}
	if err := blockPrivateIPs("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("public IP should be allowed, got %v", err)
	}
	AllowPrivate.Store(true)
	if err := blockPrivateIPs("tcp", "127.0.0.1:8080", nil); err != nil {
		t.Errorf("AllowPrivate should permit loopback, got %v", err)
	}
}

func TestSameOrigin(t *testing.T) {
	mk := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	if !sameOrigin(mk("http://a.com/x"), mk("http://a.com/y")) {
		t.Error("same host+scheme should be same origin")
	}
	if sameOrigin(mk("http://a.com"), mk("http://b.com")) {
		t.Error("different host must differ")
	}
	if sameOrigin(mk("http://a.com:80"), mk("http://a.com:81")) {
		t.Error("different port must differ")
	}
	if sameOrigin(mk("http://a.com"), mk("https://a.com")) {
		t.Error("different scheme must differ")
	}
}
