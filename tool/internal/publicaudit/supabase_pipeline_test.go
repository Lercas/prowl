package publicaudit_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const supabaseFixturePublic = "sb_publishable_q7Mn9Jk3Qw5Er8Ty2Ui6Op4As1Df0Gh9Lz"

func supabaseFixtureAnon() string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"anon","iat":1700000000,"exp":2100000000}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte("q7Mn9Jk3Qw5Er8Ty2Ui6Op4As1Df0Gh9"))
}

func ownedSupabase(t *testing.T) (*publicaudit.Auditor, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "HEAD" || r.URL.Path != "/rest/v1/owned_table" || r.URL.RawQuery != "limit=1" || r.Header.Get("apikey") == "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Prefer") != "" || r.Header.Get("Accept-Profile") != "public" {
			t.Error("wrong Supabase read contract")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Range", "0-0/*")
		w.Header().Set("X-Private-Data", "PRIVATE_RESPONSE_MUST_NOT_BE_REPORTED")
	}))
	t.Cleanup(server.Close)
	local, _ := url.Parse(server.URL)
	auditor, err := publicaudit.NewWithOwnedTargets(fixtureTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "abcdefghijklmnopqrst.supabase.co" || r.URL.Scheme != "https" {
			t.Fatal("wrong exact post-ML project binding")
		}
		copy := r.Clone(r.Context())
		u := *r.URL
		u.Scheme, u.Host = local.Scheme, local.Host
		copy.URL = &u
		return http.DefaultTransport.RoundTrip(copy)
	}), nil, []string{"owned_table"})
	if err != nil {
		t.Fatal(err)
	}
	return auditor, &calls
}

func supabasePipeline(t *testing.T, auditor *publicaudit.Auditor, ml bool) *scan.Pipeline {
	t.Helper()
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	options := scan.Options{Detector: detect.New(tax), PublicAuditor: auditor, AllOccurrences: true}
	if ml {
		options.ML = survivorScorer{}
	}
	return scan.New(options)
}

func TestSupabaseExactPostMLBindingsThroughOwnedHTTP(t *testing.T) {
	for _, key := range []string{supabaseFixturePublic, supabaseFixtureAnon()} {
		for _, fixture := range []struct{ path, text string }{
			{"owned.js", `const one={supabaseUrl:"https://abcdefghijklmnopqrsu.supabase.co",SUPABASE_ANON_KEY:"KEY"},two={supabaseUrl:"https://abcdefghijklmnopqrst.supabase.co",SUPABASE_ANON_KEY:"KEY"};`},
			{"owned.json", `{"one":{"supabaseUrl":"https://abcdefghijklmnopqrsu.supabase.co","SUPABASE_ANON_KEY":"KEY"},"two":{"supabaseUrl":"https://abcdefghijklmnopqrst.supabase.co","SUPABASE_ANON_KEY":"KEY"}}`},
			{"owned.yaml", "one: {supabaseUrl: 'https://abcdefghijklmnopqrsu.supabase.co', SUPABASE_ANON_KEY: 'KEY'}\ntwo: {supabaseUrl: 'https://abcdefghijklmnopqrst.supabase.co', SUPABASE_ANON_KEY: 'KEY'}\n"},
			{"owned.toml", "[one]\nsupabaseUrl='https://abcdefghijklmnopqrsu.supabase.co'\nSUPABASE_ANON_KEY='KEY'\n[two]\nsupabaseUrl='https://abcdefghijklmnopqrst.supabase.co'\nSUPABASE_ANON_KEY='KEY'\n"},
		} {
			t.Run(fixture.path+fmt.Sprint(len(key)), func(t *testing.T) {
				auditor, calls := ownedSupabase(t)
				coverage := model.NewCoverage()
				ctx := model.WithCoverage(t.Context(), coverage)
				// Populate the exact key without rewriting its field name.
				text := strings.ReplaceAll(fixture.text, "\"KEY\"", fmt.Sprintf("%q", key))
				text = strings.ReplaceAll(text, "'KEY'", "'"+key+"'")
				want := 1
				if key != supabaseFixturePublic {
					// Structurally checked JWTs retain the existing ML exemption.
					text = strings.ReplaceAll(text, "abcdefghijklmnopqrsu", "abcdefghijklmnopqrst")
					want = 2
				}
				fs := supabasePipeline(t, auditor, true).Findings(ctx, model.Item{Source: "code", Path: fixture.path, Text: text})
				complete, _, _ := coverage.Snapshot()
				if len(fs) != want || calls.Load() != 1 || !complete {
					t.Fatal("public audit scope/order/liveness changed", len(fs), calls.Load(), complete)
				}
				for _, finding := range fs {
					if finding.PublicKeyAudit == nil || finding.PublicKeyAudit.Status != "public_read_allowed" || finding.Verified != nil || finding.Verification != nil {
						t.Fatal("audit changed liveness or lost observation")
					}
				}
				raw, _ := json.Marshal(fs)
				for _, private := range []string{key, "PRIVATE_RESPONSE_MUST_NOT_BE_REPORTED"} {
					if strings.Contains(string(raw), private) {
						t.Fatal("key or response data serialized")
					}
				}
			})
		}
	}
}

func TestSupabaseUnknownOrCrossObjectBindingMakesCoverageIncomplete(t *testing.T) {
	for _, fixture := range []struct{ path, text string }{
		{"owned.js", `const one={supabaseUrl:"https://abcdefghijklmnopqrst.supabase.co"},two={SUPABASE_ANON_KEY:"KEY"};`},
		{"owned.json", `{"supabaseUrl":"https://abcdefghijklmnopqrst.supabase.co","SUPABASE_URL":42,"SUPABASE_ANON_KEY":"KEY"}`},
		{"owned.yaml", "supabaseUrl: 'https://abcdefghijklmnopqrst.supabase.co'\nSUPABASE_URL: false\nSUPABASE_ANON_KEY: 'KEY'\n"},
		{"owned.toml", "supabaseUrl='https://abcdefghijklmnopqrst.supabase.co'\nSUPABASE_URL=42\nSUPABASE_ANON_KEY='KEY'\n"},
	} {
		auditor, calls := ownedSupabase(t)
		coverage := model.NewCoverage()
		text := strings.ReplaceAll(fixture.text, "\"KEY\"", fmt.Sprintf("%q", supabaseFixturePublic))
		text = strings.ReplaceAll(text, "'KEY'", "'"+supabaseFixturePublic+"'")
		fs := supabasePipeline(t, auditor, false).Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: fixture.path, Text: text})
		complete, _, _ := coverage.Snapshot()
		if len(fs) != 2 || fs[0].PublicKeyAudit == nil || fs[0].PublicKeyAudit.Status != "inconclusive" || !model.IsIncompleteFinding(fs[1]) || calls.Load() != 0 || complete {
			t.Fatal("unsafe binding reached transport or claimed coverage", fixture.path, len(fs), calls.Load(), complete)
		}
	}
}
