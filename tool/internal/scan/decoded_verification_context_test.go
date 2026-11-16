package scan

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/credentialset"
	"github.com/Lercas/prowl/tool/internal/model"
)

func TestDecodedVerificationCannotBorrowOuterCompanions(t *testing.T) {
	allowOrderFixture(t)
	const key = "AKIANAFGYOEYPXU1DSYP"
	for _, codec := range []string{"base64", "hex", "gzip-base64"} {
		for _, mode := range []string{"own", "missing", "ambiguous", "cross-file", "unbound-mobile"} {
			t.Run(codec+"/"+mode, func(t *testing.T) {
				var calls atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Header.Get("X-Account") != "tenant_a" {
						t.Error("decoded verifier borrowed outer companion")
					}
					w.WriteHeader(200)
				}))
				defer srv.Close()
				payload := "account=tenant_a\nAWS=" + key
				switch mode {
				case "missing":
					payload = "AWS=" + key
				case "ambiguous":
					payload += "\naccount=tenant_b"
				}
				var encoded string
				switch codec {
				case "hex":
					encoded = hex.EncodeToString([]byte(payload))
				case "gzip-base64":
					var compressed bytes.Buffer
					writer := gzip.NewWriter(&compressed)
					if _, err := writer.Write([]byte(payload)); err != nil {
						t.Fatal(err)
					}
					if err := writer.Close(); err != nil {
						t.Fatal(err)
					}
					encoded = base64.StdEncoding.EncodeToString(compressed.Bytes())
				default:
					encoded = base64.StdEncoding.EncodeToString([]byte(payload))
				}
				item := model.Item{Source: "code", Path: "production.env", Text: "account=tenant_b\npayload=\"" + encoded + "\"\n"}
				options := Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, "extract:\n  account: 'tenant_[ab]'\n")}
				switch mode {
				case "cross-file":
					options.CrossFile = true
					item.CredentialScope = credentialset.NewScope()
				case "unbound-mobile":
					item.Meta = map[string]any{"source_transform": "mobile-printable-strings"}
				}
				fs, _ := runComponentItems(t, options, []model.Item{item})
				found := false
				for _, f := range fs {
					if f.Type != "aws_access_key_id" {
						continue
					}
					found = true
					if mode == "own" {
						if f.Verified == nil || !*f.Verified || calls.Load() != 1 {
							t.Fatal("own decoded companion was lost")
						}
					} else if f.Verified != nil || f.Verification == nil || f.Verification.Status != "error" || calls.Load() != 0 {
						t.Fatal("invalid/unbound decoded context reached provider")
					}
				}
				if !found {
					t.Fatal("decoded primary disappeared")
				}
			})
		}
	}
}

func TestInvalidDecodedVerificationSpanNeverProbes(t *testing.T) {
	allowOrderFixture(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer srv.Close()
	set := orderVerifier(t, srv.URL, "")
	for _, start := range []int{-1, 0, 100} {
		candidate := verificationCandidate{typ: "aws_access_key_id", value: "AKIANAFGYOEYPXU1DSYP", decodedText: "unrelated decoded text", decodedStart: start}
		var f model.Finding
		candidate.apply(t.Context(), set, nil, "", "production.env", &f)
		if f.Verified != nil || f.Verification == nil || f.Verification.Status != "error" || calls.Load() != 0 {
			t.Fatal("unproven decoded span reached provider")
		}
	}
}
