package publicaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

const ownedGoogleName = "projects/12345678/locations/global/keys/owned-key"
const ownedGoogleToken = "owned-operator-token"

func TestGoogleRestrictionMetadataClassification(t *testing.T) {
	for _, tc := range []struct {
		name, restrictions, status string
		capabilities               int
	}{
		{"absent", "", "unrestricted", 2}, {"empty", `{}`, "unrestricted", 2},
		{"api-only", `{"apiTargets":[{"service":"maps.googleapis.com"}]}`, "unrestricted", 1},
		{"client-only", `{"browserKeyRestrictions":{"allowedReferrers":["https://owned.invalid/*"]}}`, "unrestricted", 1},
		{"browser", `{"browserKeyRestrictions":{"allowedReferrers":["*"]},"apiTargets":[{"service":"maps.googleapis.com","methods":["Get*"]}]}`, "restrictions_configured", 0},
		{"server", `{"serverKeyRestrictions":{"allowedIps":["192.0.2.1","2001:db8::/32"]},"apiTargets":[{"service":"maps.googleapis.com","methods":[]}]}`, "restrictions_configured", 0},
		{"android", `{"androidKeyRestrictions":{"allowedApplications":[{"packageName":"com.owned.app","sha1Fingerprint":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]},"apiTargets":[{"service":"maps.googleapis.com"}]}`, "restrictions_configured", 0},
		{"ios", `{"iosKeyRestrictions":{"allowedBundleIds":["com.owned.app"]},"apiTargets":[{"service":"maps.googleapis.com"}]}`, "restrictions_configured", 0},
		{"null", `null`, "inconclusive", 0}, {"unknown", `{"futureClientRestriction":{}}`, "inconclusive", 0},
		{"case", `{"ApiTargets":[]}`, "inconclusive", 0}, {"duplicate", `{"apiTargets":[],"apiTargets":[]}`, "inconclusive", 0},
		{"api-null", `{"apiTargets":null}`, "inconclusive", 0}, {"method-null", `{"apiTargets":[{"service":"maps.googleapis.com","methods":null}]}`, "inconclusive", 0},
		{"empty-client", `{"browserKeyRestrictions":{}}`, "inconclusive", 0},
		{"empty-list", `{"browserKeyRestrictions":{"allowedReferrers":[]}}`, "inconclusive", 0},
		{"two-clients", `{"browserKeyRestrictions":{"allowedReferrers":["owned"]},"iosKeyRestrictions":{"allowedBundleIds":["com.owned"]}}`, "inconclusive", 0},
		{"bad-ip", `{"serverKeyRestrictions":{"allowedIps":["private-response"]}}`, "inconclusive", 0},
		{"bad-sha", `{"androidKeyRestrictions":{"allowedApplications":[{"packageName":"com.owned","sha1Fingerprint":"private-response"}]}}`, "inconclusive", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"name":"` + ownedGoogleName + `","displayName":"private-response"`
			if tc.restrictions != "" {
				body += `,"restrictions":` + tc.restrictions
			}
			body += `}`
			result := parseGoogleRestrictions([]byte(body), ownedGoogleName)
			if result.Status != tc.status || len(result.Capabilities) != tc.capabilities || result.Provider != "google" || len(result.Checks) == 0 {
				t.Fatal("incorrect metadata classification", result)
			}
			data, _ := json.Marshal(result)
			if strings.Contains(string(data), "private-response") || strings.Contains(string(data), ownedGoogleName) {
				t.Fatal("raw key metadata escaped into report")
			}
		})
	}
	for _, body := range []string{`{"name":"other"}`, `{"name":"` + ownedGoogleName + `","serviceAccountEmail":"owned@example.invalid"}`, `{"name":"` + ownedGoogleName + `","deleteTime":"2026-01-01T00:00:00Z"}`, `{"name":"` + ownedGoogleName + `","keyString":"private-response"}`, `{"name":"` + ownedGoogleName + `","Name":"` + ownedGoogleName + `"}`} {
		if parseGoogleRestrictions([]byte(body), ownedGoogleName).Status != "inconclusive" {
			t.Fatal("unsupported metadata certified configured or unrestricted")
		}
	}
}

func TestGoogleMetadataUsesOnlyAuthenticatedFixedGETsAndCaches(t *testing.T) {
	var calls atomic.Int32
	a := testAuditor(func(r *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		if r.Method != "GET" || r.URL.Scheme != "https" || r.URL.Host != "apikeys.googleapis.com" || r.Body != nil || r.Header.Get("Authorization") != "Bearer "+ownedGoogleToken {
			t.Error("unsafe metadata request")
		}
		body := `{"parent":"projects/12345678/locations/global","name":"` + ownedGoogleName + `"}`
		if n == 1 {
			if r.URL.Path != "/v2/keys:lookupKey" || r.URL.Query().Get("keyString") != firebaseKey {
				t.Error("incorrect lookup")
			}
		} else {
			if r.URL.Path != "/v2/"+ownedGoogleName || r.URL.RawQuery != "" {
				t.Error("incorrect resource GET")
			}
			body = `{"name":"` + ownedGoogleName + `"}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	if err := a.configureGoogleRestrictions(ownedGoogleToken); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			result := a.Audit(t.Context(), "gcp_api_key", firebaseKey, nil)
			if result.Status != "unrestricted" {
				t.Error("lost cached restrictions")
			}
			result.Checks[0].Reason = "caller mutation"
		})
	}
	wg.Wait()
	if calls.Load() != 2 || a.Audit(t.Context(), "gcp_api_key", firebaseKey, nil).Checks[0].Reason == "caller mutation" {
		t.Fatal("request cache or defensive clone failed")
	}
	text := fmt.Sprintf("%v %#v %v", a, a, a.Policy())
	if strings.Contains(text, ownedGoogleToken) {
		t.Fatal("operator credential in diagnostics or policy")
	}
}

func TestGoogleRestrictionsRejectCredentialsAndInvalidOwnershipBeforeGet(t *testing.T) {
	for _, token := range []string{"", "contains space", "contains\nline", strings.Repeat("a", 8193)} {
		if New(0).configureGoogleRestrictions(token) == nil {
			t.Fatal("invalid OAuth credential accepted")
		}
	}
	for _, body := range []string{`{"parent":"projects/12345678/locations/global","name":"https://private.invalid/key"}`, `{"parent":"projects/999/locations/global","name":"` + ownedGoogleName + `"}`, `{"parent":"projects/12345678/locations/global","name":"` + ownedGoogleName + `/../other"}`, `{"parent":"projects/12345678/locations/global","name":""}`, `{"parent":"projects/12345678/locations/global","name":"` + ownedGoogleName + `","name":"other"}`} {
		calls := 0
		a := testAuditor(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})
		_ = a.configureGoogleRestrictions(ownedGoogleToken)
		result := a.Audit(t.Context(), "gcp_api_key", firebaseKey, nil)
		if result.Status != "inconclusive" || calls != 1 {
			t.Fatal("invalid ownership reached resource GET")
		}
	}
}

func TestGoogleMetadataBudgetAndFirebasePartialEvidence(t *testing.T) {
	calls := 0
	a := testAuditor(func(r *http.Request) (*http.Response, error) {
		calls++
		body := `{"parent":"projects/12345678/locations/global","name":"` + ownedGoogleName + `"}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	_ = a.configureGoogleRestrictions(ownedGoogleToken)
	a.attempts = maxRequests - 1
	result := a.Audit(t.Context(), "gcp_api_key", firebaseKey, nil)
	if result.Status != "inconclusive" || calls != 1 || len(result.Checks) != 1 {
		t.Fatal("metadata GET exceeded global request budget")
	}
	result = a.Audit(t.Context(), "gcp_api_key", firebaseKey, nil)
	if result.Status != "inconclusive" || calls != 1 || len(result.Checks) != 1 {
		t.Fatal("exhausted audit lost check or sent request")
	}
	google := parseGoogleRestrictions([]byte(`{"name":"`+ownedGoogleName+`"}`), ownedGoogleName)
	combined := mergeGoogleAudit(google, &model.PublicKeyAudit{Provider: "firebase", Status: "inconclusive", Checks: []model.PublicAuditCheck{{Service: "rtdb", Status: "public_read_allowed"}}})
	if combined.Status != "inconclusive" || len(combined.Checks) != 3 || !combined.HasAccessObservation() {
		t.Fatal("partial Google/Firebase observations lost")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if a.Audit(canceled, "gcp_api_key", firebaseKey, nil).Status != "inconclusive" || calls != 1 {
		t.Fatal("canceled metadata request escaped")
	}
}

func TestGoogleMetadataFailuresNeverFollowRedirectsOrExposeResponses(t *testing.T) {
	for _, status := range []int{302, 401, 403, 404, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			a := testAuditor(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://private.invalid/credential"}}, Body: io.NopCloser(strings.NewReader("private-response"))}, nil
			})
			_ = a.configureGoogleRestrictions(ownedGoogleToken)
			got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, nil)
			if calls != 1 || got.Status != "inconclusive" {
				t.Fatal("denial or redirect became a policy claim")
			}
			encoded, _ := json.Marshal(got)
			if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), ownedGoogleToken) {
				t.Fatal("private error response escaped")
			}
		})
	}
	for _, body := range []string{strings.Repeat("x", maxBody+1), `{"parent":"projects/12345678/locations/global","name":"` + ownedGoogleName + `"} trailing`} {
		calls := 0
		a := testAuditor(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})
		_ = a.configureGoogleRestrictions(ownedGoogleToken)
		if got := a.Audit(t.Context(), "gcp_api_key", firebaseKey, nil); calls != 1 || got.Status != "inconclusive" {
			t.Fatal("invalid lookup accepted")
		}
	}
}

func FuzzGoogleRestrictionMetadata(f *testing.F) {
	for _, seed := range []string{`{"name":"` + ownedGoogleName + `"}`, `{"name":"` + ownedGoogleName + `","restrictions":{}}`, `{"name":"` + ownedGoogleName + `","restrictions":{"apiTargets":null}}`, `{"name":"` + ownedGoogleName + `","restrictions":{"browserKeyRestrictions":{"allowedReferrers":["private-response"]}}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			return
		}
		result := parseGoogleRestrictions([]byte(body), ownedGoogleName)
		if result.Status != "unrestricted" && result.Status != "restrictions_configured" && result.Status != "inconclusive" || len(result.Checks) > 2 {
			t.Fatal("invalid result contract")
		}
		data, _ := json.Marshal(result)
		for _, hidden := range []string{ownedGoogleName, ownedGoogleToken, firebaseKey, "private-response"} {
			if strings.Contains(string(data), hidden) {
				t.Fatal("metadata or credential value escaped into result")
			}
		}
	})
}
