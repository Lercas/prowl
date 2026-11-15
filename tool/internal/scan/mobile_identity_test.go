package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

func TestMobileIdentitySeparatesAcquisitionsWithoutChangingML(t *testing.T) {
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join(t.TempDir(), "owned.yaml")
	if err := os.WriteFile(rulePath, []byte("id: mobile-custom\ninfo:\n  name: Mobile fixture\n  severity: high\nmatchers:\n  - type: regex\n    regex: ['CUSTOM_[A-Za-z0-9]+']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load(rulePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		encScanSecret + "\nCUSTOM_Zx7Q9Rt5Uv3W8Np2",
		`{"key":"` + escapedJSON(encScanSecret) + `"}`,
	} {
		var first []model.Finding
		var firstRows []mlscore.Record
		for i, selection := range []string{"PRIVATE_ONE", "PRIVATE_TWO", "PRIVATE_ONE"} {
			var rows []mlscore.Record
			it := model.Item{Source: "mobile", Path: "app.apk!/assets/prod.json", ArtifactURI: "mobile+https://example.invalid/app.apk#/assets/prod.json", IdentityPath: "mobile+https://example.invalid/app.apk#/assets/prod.json\x00acquisition\x00https://alice:PRIVATE_AUTH@example.invalid/app.apk?signature=" + selection, MobileEntry: 1, Text: text}
			p := New(Options{Detector: detector(t), Rules: engine, ML: publicRecordScorer{&rows}, IdentityKey: bytes.Repeat([]byte{7}, 32), ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
			fs := p.Findings(t.Context(), it)
			if len(fs) == 0 {
				t.Fatal("fixture produced no finding")
			}
			if i == 0 {
				first, firstRows = fs, rows
			}
			if !reflect.DeepEqual(firstRows, rows) {
				t.Fatal("private source identity entered ML records")
			}
			for j, f := range fs {
				if f.Path != it.Path || f.IndexPath != it.ArtifactURI || f.MobileEntry != 1 || f.SourceIdentity == "" {
					t.Fatal("mobile identity lost display, member URI, or ordinal")
				}
				if f.SecretID != first[j].SecretID || f.ValueFingerprint != first[j].ValueFingerprint {
					t.Fatal("source selection changed value identity")
				}
				equal := i != 1
				if (f.Fingerprint == first[j].Fingerprint) != equal || (f.OccurrenceID == first[j].OccurrenceID) != equal || (f.IndexLocationID == first[j].IndexLocationID) != equal {
					t.Fatal("private acquisition selector did not isolate identities")
				}
			}
			raw, err := json.Marshal(fs)
			if err != nil || bytes.Contains(raw, []byte("PRIVATE_")) {
				t.Fatal("private identity leaked into findings JSON")
			}
			it.MobileEntry = 2
			duplicate := p.Findings(t.Context(), it)
			for j, f := range duplicate {
				if f.Fingerprint != fs[j].Fingerprint || f.OccurrenceID == fs[j].OccurrenceID || f.IndexLocationID == fs[j].IndexLocationID {
					t.Fatal("duplicate entry lost physical observation identity")
				}
			}
		}
	}
}

func TestMobileKeylessFingerprintUsesPublicNamespace(t *testing.T) {
	p := New(Options{Detector: detector(t)})
	it := model.Item{Source: "mobile", Path: "app.apk!/prod.env", Text: encScanSecret, ArtifactURI: "mobile+file:///one/app.apk#/prod.env", IdentityPath: "PRIVATE_ONE"}
	first := p.Findings(t.Context(), it)
	it.IdentityPath = "PRIVATE_TWO"
	second := p.Findings(t.Context(), it)
	it.ArtifactURI = "mobile+file:///two/app.apk#/prod.env"
	third := p.Findings(t.Context(), it)
	if len(first) != 1 || len(second) != 1 || len(third) != 1 || first[0].Fingerprint != second[0].Fingerprint || first[0].Fingerprint == third[0].Fingerprint {
		t.Fatal("keyless identity used private selection or collapsed public archives")
	}
}

func TestMobileReconstructionRetainsPrivateIdentity(t *testing.T) {
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	p := New(Options{Detector: detector(t), Reconstruct: true, IdentityKey: bytes.Repeat([]byte{7}, 32), ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
	it := model.Item{Source: "mobile", Path: "app.apk!/assets/bundle.js", ArtifactURI: "mobile+file:///one/app.apk#/assets/bundle.js", IdentityPath: "private-one", MobileEntry: 1, Text: "const head='AKIA';\nconst value=head+'NAFGYOEYPXU1DSYP';"}
	first := p.Findings(t.Context(), it)
	it.IdentityPath = "private-two"
	second := p.Findings(t.Context(), it)
	if len(first) != 1 || len(second) != 1 || !strings.HasPrefix(first[0].Stage, "reconstructed/") || first[0].SecretID != second[0].SecretID || first[0].Fingerprint == second[0].Fingerprint || first[0].IndexLocationID == second[0].IndexLocationID || first[0].OccurrenceID == second[0].OccurrenceID || first[0].MobileEntry != 1 {
		t.Fatal("reconstructed mobile value lost acquisition identity")
	}
}

func TestMobilePrintableStringsRuleCannotEstablishPublicBindings(t *testing.T) {
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	fs := New(Options{Detector: detector(t), Rules: engine, PublicAuditor: auditFunc(func(_ context.Context, typ, key string, fields map[string]string) *model.PublicKeyAudit {
		calls++
		if fields["app_id"] != "" {
			t.Fatal("derived rule acquired a companion")
		}
		return publicaudit.Inconclusive("missing application binding")
	})}).Findings(t.Context(), model.Item{Source: "mobile", Path: "app.apk!/assets/prod.json", Text: `{"app_id":"ABCDEF1234","algolia_api_key":"` + auditTestKey + `"}`, Meta: map[string]any{"source_transform": "mobile-printable-strings"}})
	if calls != 1 || len(fs) == 0 {
		t.Fatal("derived rule fixture did not reach audit")
	}
}

func TestMobilePrintableStringsCannotEstablishVerificationCompanions(t *testing.T) {
	allowOrderFixture(t)
	for _, composite := range []bool{false, true} {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
		extra := ""
		if composite {
			extra = "extract:\n  account: 'tenant_[ab]'\n"
		}
		fs := New(Options{Detector: detector(t), Verifiers: orderVerifier(t, srv.URL, extra)}).Findings(t.Context(), model.Item{Source: "mobile", Path: "app.apk!/assets/prod.json", Text: `{"account":"tenant_a","key":"AKIANAFGYOEYPXU1DSYP"}`, Meta: map[string]any{"source_transform": "mobile-printable-strings"}})
		srv.Close()
		want := int32(1)
		if composite {
			want = 0
		}
		wantFindings := 1
		if composite {
			wantFindings = 2
		}
		if len(fs) != wantFindings || calls.Load() != want {
			t.Fatalf("composite=%v: findings=%d requests=%d want=%d: %+v", composite, len(fs), calls.Load(), want, fs)
		}
	}
}

func TestMobilePrintableStringsCannotEstablishPublicBindings(t *testing.T) {
	for _, tc := range []struct{ path, text string }{
		{"app.apk!/res/values/strings.xml", xmlResourceFixture("owned-project", xmlGoogleKey)},
		{"app.ipa!/Payload/App/GoogleService-Info.plist", xmlPlistFixture("owned-project", xmlGoogleKey)},
		{"app.apk!/assets/prod.json", `{"apiKey":"` + xmlGoogleKey + `","projectId":"owned-project","databaseURL":"https://owned-project.firebaseio.com"}`},
	} {
		calls := 0
		coverage := model.NewCoverage()
		fs := New(Options{Detector: detector(t), PublicAuditor: auditFunc(func(_ context.Context, typ, key string, fields map[string]string) *model.PublicKeyAudit {
			calls++
			if key != xmlGoogleKey || fields["firebaseConfig"] != "derived mobile strings" || len(fields) != 1 {
				t.Fatal("synthetic string view established a Firebase companion")
			}
			return publicaudit.Inconclusive("derived mobile strings")
		})}).Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "mobile", Path: tc.path, Text: tc.text, Meta: map[string]any{"source_transform": "mobile-printable-strings"}})
		complete, _, _ := coverage.Snapshot()
		if calls != 1 || len(fs) == 0 || complete {
			t.Fatal("derived Firebase view did not remain incomplete")
		}
		for _, f := range fs {
			if strings.Contains(f.Type, "gcp") && f.PublicKeyAudit == nil {
				t.Fatal("audit disposition lost")
			}
		}
	}
}
