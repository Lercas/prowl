package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/secretindex"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func jwtSourceFixture(payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".q7Mn9Jk3Qw5Er8Ty2Ui6Op4As1Df0Gh9"
}

func TestJWTPayloadPipelineCoordinatesPrivacyMLAndKeyedIdentity(t *testing.T) {
	const password = "R7v!K9pX2mQ"
	const aws = "AKIANAFGYOEYPXU1DSYP"
	token := jwtSourceFixture(fmt.Sprintf(`{"access_key":%q,"password":%q}`, aws, password))
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ path, text string }{
		{"prod.txt", "note 🚀\nTOKEN=" + token},
		{"prod.js", `const config={token:"` + token + `"};`},
		{"prod.json", `{"note":"🚀","token":"` + token + `"}`},
		{"prod.yaml", "note: 🚀\ntoken: '" + token + "'\n"},
		{"prod.toml", "note='🚀'\ntoken='" + token + "'\n"},
	} {
		t.Run(fixture.path, func(t *testing.T) {
			var rows []mlscore.Record
			coverage := model.NewCoverage()
			fs := New(Options{Detector: detector(t), ML: publicRecordScorer{&rows}, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location}).Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: fixture.path, Text: fixture.text})
			if len(fs) != 3 || len(rows) != 3 || !model.NewResult(fs, coverage).Complete {
				t.Fatal("JWT/children lost or became incomplete", len(fs), len(rows))
			}
			found := map[string]bool{}
			for _, f := range fs {
				if f.ByteStart < 0 || f.ByteStart >= f.ByteEnd || f.ByteEnd > len(fixture.text) || f.Context != nil || f.Verified != nil || f.Verification != nil {
					t.Fatal("privacy/liveness/source mapping changed")
				}
				line, col := newLineIndex(fixture.text).cols(f.ByteStart)
				if f.Line != line || f.Col != col || f.IndexLocationID != id.Location("code", fixture.path, line, col) {
					t.Fatal("synthetic location escaped report")
				}
				for _, value := range []string{token, aws, password} {
					if f.ValueFingerprint == id.Fingerprint(value) {
						found[value] = true
					}
				}
				for _, e := range f.Evidence {
					if e.Start < 0 || e.Start >= e.End || e.End > len(fixture.text) {
						t.Fatal("proof escaped structured source")
					}
				}
			}
			if len(found) != 3 {
				t.Fatal("decoded value lost keyed identity")
			}
			scoredPassword := false
			for _, row := range rows {
				if row.Value == password {
					scoredPassword = strings.EqualFold(row.Context.Name, "password") && strings.Contains(row.Context.Line, password)
				}
			}
			if !scoredPassword {
				t.Fatal("ML lost decoded field context")
			}
			raw, _ := json.Marshal(fs)
			for _, value := range []string{token, aws, password} {
				if strings.Contains(string(raw), value) {
					t.Fatal("JWT/claims disclosed by default")
				}
			}
		})
	}
}

func TestJWTChildCannotBorrowCompanionsForVerification(t *testing.T) {
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(200) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "owned.yaml")
	rule := "id: stripe\nmatch: [stripe]\nextract:\n  account: 'tenant_[ab]'\nrequests:\n  - method: GET\n    url: " + server.URL + "\n    headers:\n      Authorization: 'Bearer {{secret}}'\n      X-Account: '{{account}}'\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(path, []byte(rule), 0600); err != nil {
		t.Fatal(err)
	}
	const stripe = "sk_live_Q5t7U9i2O4p6A8s0D3f5G7h9"
	token := jwtSourceFixture(fmt.Sprintf(`{"token":%q,"account":"tenant_a"}`, stripe))
	for _, fixture := range []struct{ path, text string }{
		{"prod.txt", "account=tenant_a\nTOKEN=" + token},
		{"prod.json", fmt.Sprintf(`{"account":"tenant_a","token":%q}`, token)},
	} {
		set, err := verify.Load(time.Second, path)
		if err != nil {
			t.Fatal(err)
		}
		fs := New(Options{Detector: detector(t), Verifiers: set}).Findings(t.Context(), model.Item{Source: "code", Path: fixture.path, Text: fixture.text})
		found := false
		for _, f := range fs {
			if f.Type == "stripe_secret_key" {
				found = f.Verified == nil && f.Verification != nil && f.Verification.Status == "error"
			}
		}
		if !found || calls != 0 {
			t.Fatal("claims borrowed a companion or verification disappeared", fixture.path, calls)
		}
	}
}

func TestJWTChildPublicAuditReceivesNoEnclosingBindings(t *testing.T) {
	const key = "AIzaSy9Qw7Er5Ty3Ui1Op8As6Df4Gh2Jk0Lz5Xc"
	token := jwtSourceFixture(fmt.Sprintf(`{"apiKey":%q,"projectId":"inner-project"}`, key))
	calls := 0
	audit := auditFunc(func(_ context.Context, typ, value string, bindings map[string]string) *model.PublicKeyAudit {
		if typ == "gcp_api_key" {
			calls++
			if value != key || len(bindings) != 0 {
				t.Fatal("JWT claims borrowed a public resource configuration")
			}
		}
		return nil
	})
	text := fmt.Sprintf(`{"projectId":"outer-project","databaseURL":"https://outer-project.firebaseio.com","token":%q}`, token)
	fs := New(Options{Detector: detector(t), PublicAuditor: audit}).Findings(t.Context(), model.Item{Source: "code", Path: "prod.json", Text: text})
	if len(fs) != 2 || calls != 1 {
		t.Fatal("public audit child missing", len(fs), calls)
	}
}

func TestJWTEscapedPasswordPreservesScoringValueAndContext(t *testing.T) {
	for _, value := range []string{"R7v!\"K9pX2mQ", "R7v!\nK9pX2mQ", "R7v!\\K9pX2mQ"} {
		payload, _ := json.Marshal(map[string]string{"password": value})
		token := jwtSourceFixture(string(payload))
		var rows []mlscore.Record
		fs := New(Options{Detector: detector(t), ML: publicRecordScorer{&rows}}).Findings(t.Context(), model.Item{Source: "code", Path: "prod.json", Text: fmt.Sprintf(`{"token":%q}`, token)})
		if len(fs) != 2 {
			t.Fatal("escaped credential lost")
		}
		found := false
		for _, r := range rows {
			if r.Value == value {
				found = r.Context.Name == "password" && strings.Contains(r.Context.Line, strconv.Quote(value))
			}
		}
		if !found {
			t.Fatal("scoring context used JSON spelling or a truncated line")
		}
	}
}
