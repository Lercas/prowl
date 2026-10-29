package safehttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// InferenceClient permits only a pinned loopback service by default. It never
// changes the global address policy; remote services require opt-in and TLS.
func InferenceClient(raw string, allowRemote bool, timeout time.Duration) (*http.Client, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("invalid inference endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	local := strings.EqualFold(u.Hostname(), "localhost") || ip != nil && ip.IsLoopback()
	if !local && (!allowRemote || u.Scheme != "https") {
		return nil, errors.New("remote inference requires explicit opt-in and HTTPS")
	}
	c := Client(timeout)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("inference redirects are disabled") }
	if !local {
		return c, nil
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	d := net.Dialer{Timeout: 10 * time.Second}
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(host, u.Hostname()) {
			return nil, ErrBlockedAddress
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, ErrBlockedAddress
		}
		for _, candidate := range ips {
			if !candidate.IP.IsLoopback() {
				return nil, ErrBlockedAddress
			}
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
	c.Transport = t
	return c, nil
}
