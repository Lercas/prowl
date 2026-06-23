// Package safehttp builds outbound HTTP clients hardened against SSRF and cross-host secret
// forwarding: clients refuse to dial internal address space and never carry secret-bearing
// headers across a host boundary on redirect.
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// RedactURL strips embedded credentials (user:token@) from a URL so it can't leak into a log or
// error. It splits on the last '@' within the authority, so a password containing '@' is fully
// removed while an '@' in the path is untouched. A creds-less or non-URL string is returned as-is.
func RedactURL(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return raw
	}
	rest := raw[i+3:]
	authEnd := len(rest)
	if s := strings.IndexByte(rest, '/'); s >= 0 {
		authEnd = s
	}
	at := strings.LastIndexByte(rest[:authEnd], '@')
	if at < 0 {
		return raw
	}
	return raw[:i+3] + "***@" + rest[at+1:]
}

// AllowPrivate disables the private/loopback dial guard (set from PROWL_ALLOW_PRIVATE_IPS, and by
// tests to reach 127.0.0.1 httptest servers). Atomic so the dial Control hook can read it
// concurrently with a setter.
var AllowPrivate atomic.Bool

// ErrBlockedAddress is returned by the dial control when a connection targets internal space.
var ErrBlockedAddress = errors.New("safehttp: refusing to connect to internal address")

// ErrCrossHostRedirect is returned when a redirect would leave the original host, which would
// forward custom auth headers to a third party.
var ErrCrossHostRedirect = errors.New("safehttp: refusing cross-host redirect")

// maxRedirects caps redirect depth even for same-host hops.
const maxRedirects = 5

// blockPrivateIPs is a net.Dialer Control hook. It runs post-resolution with the concrete IP the
// socket will connect to, so it rejects internal targets even under DNS rebinding.
func blockPrivateIPs(network, address string, _ syscall.RawConn) error {
	if AllowPrivate.Load() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Control always receives a resolved IP:port; a non-IP here is unexpected, so reject.
		return fmt.Errorf("%w: %s", ErrBlockedAddress, address)
	}
	if isInternal(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
	}
	return nil
}

// extraInternalV4 are non-globally-routable IPv4 blocks the stdlib IP helpers don't flag.
var extraInternalV4 = []*net.IPNet{
	mustCIDR("100.64.0.0/10"), // RFC6598 carrier-grade NAT
	mustCIDR("192.0.0.0/24"),  // RFC6890 IETF protocol assignments
	mustCIDR("198.18.0.0/15"), // RFC2544 benchmarking
}

// IPv6 transition prefixes that embed an IPv4 address; the embedded v4 must be re-checked so a
// literal like 64:ff9b::a9fe:a9fe can't smuggle the link-local metadata IP past the v4 guards.
var (
	nat64Prefix = mustCIDR("64:ff9b::/96")
	v6to4Prefix = mustCIDR("2002::/16")
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("safehttp: bad CIDR " + s + ": " + err.Error())
	}
	return n
}

// isInternal reports whether ip is loopback, link-local, private (RFC1918), ULA (fc00::/7),
// CGNAT, IETF/benchmarking ranges, unspecified, or otherwise non-globally-routable — including the
// IPv4 embedded in a NAT64 / 6to4 / IPv4-compatible address.
func isInternal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsPrivate() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// 0.0.0.0/8 "this host" range is not flagged by IsUnspecified beyond 0.0.0.0 itself.
		if v4[0] == 0 {
			return true
		}
		for _, n := range extraInternalV4 {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	// IPv6: unwrap an embedded v4 and re-check it, so an internal v4 can't be reached via a v6 literal.
	if embedded := embeddedV4(ip); embedded != nil {
		return isInternal(embedded)
	}
	return false
}

// embeddedV4 extracts the IPv4 address embedded in a NAT64 (64:ff9b::/96), 6to4 (2002::/16), or
// IPv4-compatible (::/96) IPv6 address, or nil if ip carries no such address.
func embeddedV4(ip net.IP) net.IP {
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}
	switch {
	case nat64Prefix.Contains(ip16):
		// Last 32 bits are the embedded IPv4 address.
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15]).To4()
	case v6to4Prefix.Contains(ip16):
		// 2002:V4ADDR::/48 — the V4 address is bytes 2..5.
		return net.IPv4(ip16[2], ip16[3], ip16[4], ip16[5]).To4()
	case isV4Compat(ip16):
		// ::a.b.c.d (first 96 bits zero, not ::1 or ::). Last 32 bits are the v4 address.
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15]).To4()
	}
	return nil
}

// isV4Compat reports whether ip16 is a deprecated IPv4-compatible IPv6 address (::/96 with a
// non-trivial v4 tail). :: and ::1 are excluded (handled by IsUnspecified/IsLoopback).
func isV4Compat(ip16 net.IP) bool {
	for i := 0; i < 12; i++ {
		if ip16[i] != 0 {
			return false
		}
	}
	// Exclude :: and ::1 (tail 0.0.0.0 / 0.0.0.1) which aren't meaningful embedded v4 addresses.
	tail := ip16[12:]
	if tail[0] == 0 && tail[1] == 0 && tail[2] == 0 && (tail[3] == 0 || tail[3] == 1) {
		return false
	}
	return true
}

// safeDialContext returns a DialContext whose Control hook (blockPrivateIPs) vets every resolved
// candidate IP just before connect, defeating DNS rebinding.
func safeDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control:   blockPrivateIPs,
	}
	return d.DialContext
}

// SafeTransport returns an *http.Transport whose dialer refuses internal addresses. dialTimeout
// bounds the TCP connect (0 -> default).
//
// Proxy-from-environment is off by default: with a proxy the dial guard would vet the proxy's IP,
// not the request target, so an attacker URL like http://169.254.169.254/ would bypass the SSRF
// check. It's honoured only once the operator opts into internal space via PROWL_ALLOW_PRIVATE_IPS.
func SafeTransport(dialTimeout time.Duration) *http.Transport {
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	var proxy func(*http.Request) (*url.URL, error)
	if AllowPrivate.Load() {
		proxy = http.ProxyFromEnvironment
	}
	return &http.Transport{
		Proxy:                 proxy,
		DialContext:           safeDialContext(dialTimeout),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// checkRedirect caps redirect depth and refuses any hop that changes origin. Go strips
// Authorization/Cookie cross-host but not custom headers (e.g. X-Api-Key), so a host change would
// forward a secret-bearing header to an origin the operator never targeted.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("safehttp: stopped after %d redirects", maxRedirects)
	}
	// Compare the full origin (scheme+host+port): a different port/scheme is a different service.
	// via[0] is the originally requested URL.
	if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
		return ErrCrossHostRedirect
	}
	return nil
}

// sameOrigin reports whether a and b share scheme + host + effective port. Comparison is
// case-insensitive, strips a trailing FQDN dot, and treats a default port as equal to the explicit
// one, so a legit redirect isn't wrongly blocked while a real origin change stays fail-closed.
func sameOrigin(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	ah, ap := normHostPort(a)
	bh, bp := normHostPort(b)
	return strings.EqualFold(ah, bh) && ap == bp
}

// normHostPort returns u's hostname (lower-cased, trailing dot stripped) and its effective port,
// defaulting an absent port to the scheme default (443/https, 80/http).
func normHostPort(u *url.URL) (host, port string) {
	host = strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port = u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return host, port
}

// Client returns an *http.Client with the hardened transport, the cross-host redirect guard, and
// the given overall timeout (0 -> 12s).
func Client(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     SafeTransport(timeout),
		CheckRedirect: checkRedirect,
	}
}
