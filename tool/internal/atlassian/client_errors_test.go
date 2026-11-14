package atlassian

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const clientSecretSentinel = "OWNED_CLIENT_SECRET_SENTINEL"

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientRejectsInvalidBaseBeforeTransport(t *testing.T) {
	for _, base := range []string{
		"https://user:" + clientSecretSentinel + "@[broken",
		"https://user:" + clientSecretSentinel + "@fixture.invalid/%zz",
		"https://user:" + clientSecretSentinel + "@fixture.invalid:bad",
		"https://fixture.invalid:65536/", "https://fixture.invalid:0/", "https://fixture.invalid:/",
		"https://[not-an-ip]/", "https://2001:db8::1/", "file://fixture.invalid/", "https:///missing-host",
		"https:opaque", "", "/relative", "https://fixture.invalid/\n" + clientSecretSentinel,
	} {
		for _, product := range []string{"jira", "confluence"} {
			var calls atomic.Int32
			ch, dep, err := Collect(context.Background(), base, product, Auth{}, Options{HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, errors.New("transport must not be called")
			})}})
			if err == nil || ch != nil || calls.Load() != 0 || strings.Contains(err.Error(), clientSecretSentinel) || strings.Contains(dep.BaseURL, clientSecretSentinel) {
				t.Fatalf("invalid input contacted transport or exposed credentials: product=%s calls=%d", product, calls.Load())
			}
		}
	}
}

func TestClientNormalizationKeepsContextAndDropsURLCredentials(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://user:" + clientSecretSentinel + "@fixture.invalid/ctx/?token=" + clientSecretSentinel + "#" + clientSecretSentinel, "https://fixture.invalid/ctx"},
		{"https://fixture.invalid/ctx?", "https://fixture.invalid/ctx"},
		{"https://fixture.invalid/ctx%2F/?secret=" + clientSecretSentinel, "https://fixture.invalid/ctx%2F"},
		{"http://[::1]:8080/ctx/", "http://[::1]:8080/ctx"},
	} {
		c := NewClient(pair[0], Auth{PAT: "owned-auth-token"}, 0)
		c.http = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != pair[1]+"/probe" || r.URL.User != nil || r.Header.Get("Authorization") != "Bearer owned-auth-token" {
				t.Error("request changed context path, retained URL credentials, or replaced explicit auth")
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
		})}
		if c.base != pair[1] || c.get(context.Background(), "/probe", nil, nil) != nil {
			t.Error("normalization corrupted an accepted base URL")
		}
	}
}

func TestClientErrorsDoNotPrintTransportCause(t *testing.T) {
	cause := errors.New("transport error contains " + clientSecretSentinel)
	for _, product := range []string{"jira", "confluence"} {
		base := "https://user:" + clientSecretSentinel + "@fixture.invalid/?token=" + clientSecretSentinel + "#" + clientSecretSentinel
		_, dep, err := Collect(context.Background(), base, product, Auth{}, Options{HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			return nil, cause
		})}})
		if err == nil || !errors.Is(err, cause) || strings.Contains(err.Error(), clientSecretSentinel) || dep.BaseURL != "https://fixture.invalid" {
			t.Error("detection error lost cause identity or exposed credentials")
		}
	}
}

func TestClientRateLimitErrorsAreSafeAndClosed(t *testing.T) {
	for _, status := range []int{429, 503} {
		for _, readFailure := range []bool{false, true} {
			cause := errors.New(clientSecretSentinel)
			body := &failingBody{Reader: strings.NewReader(""), closeErr: cause}
			if readFailure {
				body.readErr = cause
			}
			c := NewClient("https://fixture.invalid", Auth{}, 0)
			c.maxRetry = 0
			c.http = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: body, Request: r}, nil
			})}
			err := c.get(context.Background(), "/probe", nil, nil)
			if err == nil || !body.closed || !errors.Is(err, cause) || strings.Contains(err.Error(), clientSecretSentinel) {
				t.Error("rate-limit response error was ignored, exposed data, or left the body open")
			}
		}
	}
}

type ownedTimeoutError struct{}

func (*ownedTimeoutError) Error() string   { return clientSecretSentinel }
func (*ownedTimeoutError) Timeout() bool   { return true }
func (*ownedTimeoutError) Temporary() bool { return false }

func TestClientSafeErrorsKeepCauseClassification(t *testing.T) {
	cause := &ownedTimeoutError{}
	c := NewClient("https://fixture.invalid", Auth{}, 0)
	c.http = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) { return nil, cause })}
	err := c.get(context.Background(), "/probe", nil, nil)
	var timeout net.Error
	var wrapped *url.Error
	if !errors.Is(err, cause) || !errors.As(err, &timeout) || !timeout.Timeout() || !errors.As(err, &wrapped) || strings.Contains(err.Error(), clientSecretSentinel) {
		t.Fatal("safe error discarded transport/timeout classification or printed its cause")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.http = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		t.Error("cancelled request reached the transport")
		return nil, cause
	})}
	if err := c.get(ctx, "/probe", nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation identity lost")
	}
}

func TestClientLocalAndStatusErrorsDoNotExposeInput(t *testing.T) {
	c := NewClient("https://fixture.invalid", Auth{}, 0)
	c.http = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		t.Error("invalid request reached transport")
		return nil, errors.New("unexpected call")
	})}
	for _, call := range []func() error{
		func() error { return c.get(context.Background(), "/%"+clientSecretSentinel, nil, nil) },
		func() error { return c.post(context.Background(), "/probe", nil, make(chan string), nil) },
	} {
		if err := call(); err == nil || strings.Contains(err.Error(), clientSecretSentinel) {
			t.Fatal("local error leaked input or was accepted")
		}
	}
	err := &reqError{Status: 403, URL: "https://fixture.invalid/" + clientSecretSentinel + "?token=" + clientSecretSentinel, Body: clientSecretSentinel}
	if strings.Contains(err.Error(), clientSecretSentinel) || statusOf(err) != 403 {
		t.Fatal("HTTP status error printed secret-bearing URL/body or lost status")
	}
}
