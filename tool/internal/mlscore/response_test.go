package mlscore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type scoreRoundTripFunc func(*http.Request) (*http.Response, error)

func (f scoreRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func responseClient(body io.ReadCloser) *Client {
	c, err := NewWithPolicy("https://owned.invalid", 0.3, true)
	if err != nil {
		panic(err)
	}
	c.http.Transport = scoreRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body}, nil
	})
	return c
}

func TestScoreRejectsAmbiguousOrIncompleteResponses(t *testing.T) {
	for name, raw := range map[string]string{
		"missing score":       `{"results":[{}]}`,
		"null score":          `{"results":[{"score":null}]}`,
		"null result":         `{"results":[null]}`,
		"missing results":     `{}`,
		"null results":        `{"results":null}`,
		"negative score":      `{"results":[{"score":-0.1}]}`,
		"score above one":     `{"results":[{"score":1.1}]}`,
		"duplicate score":     `{"results":[{"score":1,"score":0}]}`,
		"case alias":          `{"results":[{"score":1,"SCORE":0}]}`,
		"escaped duplicate":   `{"results":[{"score":1,"sco\u0072e":0}]}`,
		"duplicate results":   `{"results":[{"score":1}],"results":[{"score":0}]}`,
		"results case alias":  `{"results":[{"score":1}],"RESULTS":[{"score":0}]}`,
		"trailing data":       `{"results":[{"score":0}]} PRIVATE_DIAGNOSTIC`,
		"second document":     `{"results":[{"score":0}]} {}`,
		"invalid utf8":        "{\"results\":[{\"score\":0,\"type\":\"\xff\"}]}",
		"unpaired surrogate":  `{"results":[{"score":0,"type":"\ud800"}]}`,
		"overflow":            `{"results":[{"score":1e999}]}`,
		"wrong score type":    `{"results":[{"score":"PRIVATE_DIAGNOSTIC"}]}`,
		"mixed valid invalid": `{"results":[{"score":0},{"score":null}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			recs := []Record{{Value: "owned"}}
			if name == "mixed valid invalid" {
				recs = append(recs, Record{Value: "other"})
			}
			results, err := responseClient(io.NopCloser(strings.NewReader(raw))).Score(context.Background(), recs)
			if err == nil || results != nil || strings.Contains(err.Error(), "PRIVATE_DIAGNOSTIC") {
				t.Fatalf("unsafe ML response accepted: results=%+v err=%v", results, err)
			}
		})
	}
}

func TestScoreAcceptsZeroAndOneAndSidecarMetadata(t *testing.T) {
	raw := `{"results":[{"score":0,"is_secret":false,"l2_prob":0,"l1_type":null},{"score":1,"is_secret":true,"type":"aws","stage":"L1-structured","future":{"metadata":"ok"}}]}`
	results, err := responseClient(io.NopCloser(strings.NewReader(raw))).Score(context.Background(), []Record{{Value: "one"}, {Value: "two"}})
	if err != nil || len(results) != 2 || results[0].Score != 0 || results[1].Score != 1 || !results[1].IsSecret || results[1].Type != "aws" {
		t.Fatalf("normal sidecar result changed: results=%+v err=%v", results, err)
	}
}

type faultyScoreBody struct {
	io.Reader
	readErr, closeErr error
	closed            bool
	readBytes         int
}

func (r *faultyScoreBody) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.readBytes += n
	if err == io.EOF && r.readErr != nil {
		return n, r.readErr
	}
	return n, err
}

func (r *faultyScoreBody) Close() error { r.closed = true; return r.closeErr }

func TestScoreResponseBudgetUsesActualDecodedBytes(t *testing.T) {
	const prefix = `{"results":[{"score":0}]}`
	for _, size := range []int{maxScoreResponseBytes, maxScoreResponseBytes + 1, maxScoreResponseBytes * 2} {
		body := &faultyScoreBody{Reader: strings.NewReader(prefix + strings.Repeat(" ", size-len(prefix)))}
		results, err := responseClient(body).Score(context.Background(), []Record{{Value: "one"}})
		if !body.closed || body.readBytes > maxScoreResponseBytes+1 {
			t.Fatalf("ML response read is not bounded: size=%d read=%d closed=%v", size, body.readBytes, body.closed)
		}
		if size == maxScoreResponseBytes {
			if err != nil || len(results) != 1 || results[0].Score != 0 {
				t.Fatalf("complete response at the byte limit rejected: %+v %v", results, err)
			}
		} else if err == nil || results != nil {
			t.Fatalf("oversized response used for filtering: size=%d results=%+v err=%v", size, results, err)
		}
	}
}

func TestSidecarTransportErrorsWithholdCredentialsAndKeepCause(t *testing.T) {
	for _, health := range []bool{false, true} {
		cause := errors.New("PRIVATE_DIAGNOSTIC")
		client, err := NewWithPolicy("https://owned.invalid", 0.3, true)
		if err != nil {
			t.Fatal(err)
		}
		client.http.Transport = scoreRoundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, cause })
		err = nil
		if health {
			err = client.Health(context.Background())
		} else {
			_, err = client.Score(context.Background(), []Record{{Value: "owned"}})
		}
		if !errors.Is(err, cause) || strings.Contains(err.Error(), "PRIVATE_DIAGNOSTIC") {
			t.Fatalf("unsafe sidecar transport error: health=%v err=%v", health, err)
		}
	}
}

func TestScoreReadAndCloseFailuresInvalidateTheWholeResponse(t *testing.T) {
	for _, mode := range []string{"read", "close"} {
		t.Run(mode, func(t *testing.T) {
			cause := errors.New("PRIVATE_DIAGNOSTIC")
			body := &faultyScoreBody{Reader: strings.NewReader(`{"results":[{"score":0}]}`)}
			if mode == "read" {
				body.readErr = cause
			} else {
				body.closeErr = cause
			}
			results, err := responseClient(body).Score(context.Background(), []Record{{Value: "one"}})
			if !body.closed || results != nil || !errors.Is(err, cause) || strings.Contains(err.Error(), "PRIVATE_DIAGNOSTIC") {
				t.Fatalf("unsafe response completion: closed=%v results=%+v err=%v", body.closed, results, err)
			}
		})
	}
}
