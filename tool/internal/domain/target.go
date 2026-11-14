package domain

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Target is a validated host inventory entry. URLs select their exact scheme and authority;
// bare DNS names retain the apex/www sweep. URL paths are intentionally ignored by host scans.
type Target struct {
	Host          string
	Canonical     string // A reparsable identity without URL paths, queries or fragments.
	ReconEligible bool
	roots         []string
	fallback      string
}

// ParseTarget rejects ambiguous addresses before discovery can reinterpret their authority.
// Errors omit the input, which can contain accidentally pasted credentials.
func ParseTarget(raw string) (Target, error) {
	invalid := errors.New("target must be a hostname, literal IP, host:port or HTTP(S) URL without credentials")
	raw = strings.TrimSpace(raw)
	if raw == "" || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\\\r\n\t") {
		return Target{}, invalid
	}
	explicit := strings.Contains(raw, "://")
	if !explicit {
		if ip, err := netip.ParseAddr(raw); err == nil && ip.Is6() {
			if ip.Zone() != "" {
				return Target{}, invalid
			}
			raw = "[" + ip.String() + "]"
		}
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err == nil {
		u.Scheme = strings.ToLower(u.Scheme)
	}
	if err != nil || u.User != nil || u.Opaque != "" || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return Target{}, invalid
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	ip, ipErr := netip.ParseAddr(host)
	if ipErr == nil {
		if ip.Zone() != "" {
			return Target{}, invalid
		}
		host = ip.String()
	} else {
		// Brackets and colons denote IP literals, never a DNS name or a truncated IPv6 prefix.
		if strings.ContainsAny(u.Host, "[]") || strings.Contains(host, ":") {
			return Target{}, invalid
		}
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || len(host) == 0 || len(host) > 253 {
			return Target{}, invalid
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Target{}, invalid
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return Target{}, invalid
				}
			}
		}
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return Target{}, invalid
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return Target{}, invalid
		}
		port = strconv.Itoa(n)
	}
	target := Target{Host: host, ReconEligible: ipErr != nil && port == "" && strings.Contains(host, ".")}
	if !explicit && port == "" && target.ReconEligible {
		target.Host = strings.TrimPrefix(host, "www.")
		target.Canonical = target.Host
		target.roots = []string{"https://" + target.Host, "https://www." + target.Host}
		target.fallback = "http://" + target.Host
		return target, nil
	}
	authority := host
	if ipErr == nil && ip.Is6() {
		authority = "[" + host + "]"
	}
	if port != "" {
		authority += ":" + port
	}
	target.roots = []string{u.Scheme + "://" + authority}
	target.Canonical = authority
	if explicit {
		target.Canonical = target.roots[0]
	}
	if !explicit {
		target.fallback = "http://" + authority
	}
	return target, nil
}
