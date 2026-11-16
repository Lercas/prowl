package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/reconstruct"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func reverseASCII(text string) string {
	b := []byte(text)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func TestStringOrderPipelineIdentityAndGenericBinding(t *testing.T) {
	for _, tc := range []struct{ name, value, typ, expression string }{
		{"accessKeyId", "AKIANAFGYOEYPXU1DSYP", "aws_access_key_id", `"` + reverseASCII("AKIANAFGYOEYPXU1DSYP") + `".split("").reverse().join("")`},
		{"password", "R3moteSecret9!", "generic_password", `"` + reverseASCII("R3moteSecret9!") + `".split("").reverse().join("")`},
		{"db_password", "P4ssw0rdWithSpac3s!", "generic_password", `"` + strings.Join(strings.Split("P4ssw0rdWithSpac3s!", ""), " ") + `".split(" ").join("")`},
		{"password", "私密<p4ssw0rd>z9", "generic_password", `"私密<p4ssw0rd>z9".split(" ").join("")`},
	} {
		text := "/*🚀*/ const " + tc.name + "=" + tc.expression + ";"
		for _, path := range []string{"bundle.js", "bundle.tsx", "https://owned.invalid/bundle.js?private_query=secret"} {
			scorer := &tableRecordScorer{}
			fs := New(Options{Detector: detector(t), Reconstruct: true, ML: scorer, RevealSecrets: true, ValueFingerprint: func(value string) string {
				if value != tc.value {
					return "other"
				}
				return "owned-value-identity"
			}}).Findings(t.Context(), model.Item{Source: "code", Path: path, Text: text})
			found := 0
			for _, f := range fs {
				if f.Type != tc.typ || f.Redacted != tc.value || !strings.HasPrefix(f.Stage, "reconstructed/") {
					continue
				}
				found++
				if text[f.ByteStart:f.ByteEnd] != tc.expression || f.UTF16Col != newLineIndex(text).utf16Col(f.ByteStart) || f.Fingerprint != model.ComputeFingerprint(tc.typ, path, tc.value) || f.ValueFingerprint != "owned-value-identity" || len(f.Evidence) < 3 || f.Context != nil {
					t.Fatal("lost identity or source proof", tc.name, f)
				}
			}
			if found != 1 {
				t.Fatal("lost reconstructed candidate", tc.name, path, fs)
			}
			if tc.typ == "generic_password" {
				proved := false
				for _, record := range scorer.records {
					if record.Value == tc.value && record.Context.Name == tc.name && record.DirectBinding == tc.name {
						proved = true
					}
				}
				if !proved {
					t.Fatal("ML lost parser name", scorer.records)
				}
			}
		}
	}
}

func TestStringOrderDoesNotBorrowBindingOrBypassDisabledType(t *testing.T) {
	expression := `"` + reverseASCII("R3moteSecret9!") + `".split("").reverse().join("")`
	for _, text := range []string{`const note=` + expression + `;`, `const password="unrelated";const note=` + expression + `;`, `const note="password";const x=` + expression + `;`} {
		for _, f := range New(Options{Detector: detector(t), Reconstruct: true}).Findings(t.Context(), model.Item{Source: "code", Path: "bundle.js", Text: text}) {
			if f.Type == "generic_password" && strings.HasPrefix(f.Stage, "reconstructed/") {
				t.Fatal("borrowed a foreign password name")
			}
		}
	}
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	// A configured taxonomy controls scalar nomination as well as raw scanning.
	types := tax.Types[:0]
	for _, st := range tax.Types {
		if st.ID != "generic_password" {
			types = append(types, st)
		}
	}
	tax.Types = types
	for _, f := range New(Options{Detector: detect.New(tax), Reconstruct: true}).Findings(t.Context(), model.Item{Source: "code", Path: "bundle.js", Text: `const password=` + expression + `;`}) {
		if f.Type == "generic_password" {
			t.Fatal("disabled generic password nominated")
		}
	}
}

func TestStringOrderReconstructionPolicyRevision(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		p := New(Options{Reconstruct: enabled})
		coverage := model.NewCoverage()
		p.RegisterPolicy(model.WithCoverage(context.Background(), coverage))
		_, stages := p.Capabilities()
		policy := map[string]any{"revision": DetectionRevision, "taxonomy": "", "stages": stages, "verify_all": false, "ignore_pragmas": false, "allow_callback": false, "all_occurrences": false}
		if enabled {
			policy["reconstruction_revision"] = reconstruct.Revision
		}
		expected := model.NewCoverage()
		expected.RegisterScope("detection_policy", "1.5.0", policy)
		actualScope := model.NewResult(nil, coverage).Scope
		want := model.NewResult(nil, expected).Scope[0]
		found := false
		for _, s := range actualScope {
			if s == want {
				found = true
			}
		}
		if !found {
			data, _ := json.Marshal(actualScope)
			t.Fatal("reconstruction policy lost version", enabled, string(data))
		}
	}
}

func TestStringOrderBindingDoesNotSuppressDecodedInnerPassword(t *testing.T) {
	decoded := `password="R3moteSecret9!"`
	text := `const token=atob("` + base64.StdEncoding.EncodeToString([]byte(decoded)) + `");`
	fs := New(Options{Detector: detector(t), Reconstruct: true, RevealSecrets: true}).Findings(t.Context(), model.Item{Source: "code", Path: "bundle.js", Text: text})
	found := false
	for _, f := range fs {
		if f.Type == "generic_password" && strings.HasPrefix(f.Stage, "reconstructed/") && f.Redacted == "R3moteSecret9!" {
			found = true
		}
	}
	if !found {
		t.Fatal("non-password declaration suppressed decoded inner password", fs)
	}
}

func TestStringOrderVerificationKeepsOrderingAndOriginalCompanions(t *testing.T) {
	allowOrderFixture(t)
	for _, tc := range []struct {
		name                    string
		companion, drop, all    bool
		wantCalls, wantFindings int
	}{
		{"source-companion", true, false, false, 1, 1},
		{"decoded-companion-only", false, false, false, 0, 1},
		{"ml-drop", true, true, false, 0, 0},
		{"verify-all-rescues-live", true, true, true, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer AKIANAFGYOEYPXU1DSYP" || r.Header.Get("X-Account") != "tenant_a" {
					t.Error("wrong reconstructed secret or companion")
				}
				w.WriteHeader(200)
			}))
			defer server.Close()
			tax, err := taxonomy.LoadDefault()
			if err != nil {
				t.Fatal(err)
			}
			var selected []taxonomy.SecretType
			for _, st := range tax.Types {
				if st.ID == "aws_access_key_id" {
					selected = append(selected, st)
				}
			}
			tax.Types = selected
			value := "AKIANAFGYOEYPXU1DSYP"
			prefix := `const account="tenant_a";`
			if !tc.companion {
				value += ":tenant_a"
				prefix = ""
			}
			text := prefix + `const key="` + reverseASCII(value) + `".split("").reverse().join("");`
			score := 1.
			if tc.drop {
				score = 0
			}
			fs := New(Options{Detector: detect.New(tax), Reconstruct: true, VerifyAll: tc.all, Verifiers: orderVerifier(t, server.URL, "extract:\n  account: 'tenant_a'\n"), ML: fixedMLScorer{results: []mlscore.Result{{Score: score}}, threshold: .3}}).Findings(t.Context(), model.Item{Source: "code", Path: "bundle.js", Text: text})
			var found []model.Finding
			for _, f := range fs {
				if f.Type == "aws_access_key_id" {
					found = append(found, f)
				}
			}
			if int(calls.Load()) != tc.wantCalls || len(found) != tc.wantFindings {
				t.Fatal("verification order or source context changed", calls.Load(), found)
			}
			if tc.wantCalls == 1 && (found[0].Verified == nil || !*found[0].Verified) {
				t.Fatal("owned successful provider result lost")
			}
			if !tc.companion && found[0].Verified != nil && *found[0].Verified {
				t.Fatal("decoded companion became LIVE")
			}
		})
	}
}
