package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/secretindex"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

const ownedJWTValue = "OWNED_Q7mR3vK8pT2xN6cW4bY9"

func ownedJWTRules(t testing.TB, id string) *rules.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "owned.yaml")
	text := `id: ` + id + `
info:
  name: owned JWT regression
  severity: high
matchers-condition: and
matchers:
  - type: word
    words: ['tenantScope']
  - type: regex
    regex: ['OWNED_[A-Za-z0-9]{20}']
extractors:
  - type: regex
    regex: ['(OWNED_[A-Za-z0-9]{20})']
    group: 1
`
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func jwtRuleFindings(fs []model.Finding, typ string) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

func TestJWTRulesFormatsEscapesIdentityAndContext(t *testing.T) {
	engine := ownedJWTRules(t, "owned-jwt")
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{`{"tenantScope":"owned","label":"` + ownedJWTValue + `"}`, `{"tenantScope":"owned","label":"\u004fWNED_Q7mR3vK8pT2xN6cW4bY9"}`, `{"tenant\u0053cope":"owned","label":"` + ownedJWTValue + `"}`} {
		token := jwtSourceFixture(payload)
		for _, format := range []string{"txt", "js", "json", "yaml", "toml"} {
			t.Run(format+fmt.Sprint(strings.Contains(payload, "\\")), func(t *testing.T) {
				text := "note 🚀\nTOKEN='" + token + "'\n"
				switch format {
				case "js":
					text = `const config={token:"` + token + `"};`
				case "json":
					text = `{"note":"🚀","token":"` + token + `"}`
				case "yaml":
					text = "note: 🚀\ntoken: '" + token + "'\n"
				case "toml":
					text = "note='🚀'\ntoken='" + token + "'\n"
				}
				var records []mlscore.Record
				coverage := model.NewCoverage()
				p := New(Options{Detector: detector(t), Rules: engine, ML: publicRecordScorer{&records}, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
				fs := p.Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: "prod." + format, Text: text})
				found := jwtRuleFindings(fs, "owned-jwt")
				if len(found) != 1 || !model.NewResult(fs, coverage).Complete {
					t.Fatal("payload-only template missing, duplicated or incomplete", len(found))
				}
				f := found[0]
				if !strings.Contains(f.Stage, "rule/jwt-payload") || f.ValueFingerprint != id.Fingerprint(ownedJWTValue) || f.Context != nil || f.Verified != nil || len(f.Evidence) == 0 {
					t.Fatal("rule lost identity/privacy/proof")
				}
				if f.ByteStart < strings.Index(text, token) || f.ByteEnd > strings.Index(text, token)+len(token) || f.ByteStart >= f.ByteEnd {
					t.Fatal("rule escaped encoded source")
				}
				line, col := newLineIndex(text).cols(f.ByteStart)
				if f.Line != line || f.Col != col || f.IndexLocationID != id.Location("code", "prod."+format, line, col) {
					t.Fatal("synthetic report/index coordinates")
				}
				for _, proof := range f.Evidence {
					if proof.Start < 0 || proof.Start >= proof.End || proof.End > len(text) {
						t.Fatal("invalid source proof")
					}
				}
				scored := false
				for _, record := range records {
					if record.Value == ownedJWTValue {
						scored = strings.Contains(record.Context.Line, ownedJWTValue) && record.Context.Name == "label"
					}
				}
				if !scored {
					t.Fatal("ML received encoded spelling instead of logical value")
				}
				raw, _ := json.Marshal(fs)
				if strings.Contains(string(raw), ownedJWTValue) || strings.Contains(string(raw), token) {
					t.Fatal("default output disclosed a credential")
				}
			})
		}
	}
}

func TestJWTRulesCannotReplaceChecksumProof(t *testing.T) {
	const key = "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"
	path := filepath.Join(t.TempDir(), "shadow.yaml")
	if err := os.WriteFile(path, []byte("id: owned-shadow\ninfo:\n  name: shadow\n  severity: critical\nmatchers:\n  - type: regex\n    regex: ['ghp_[A-Za-z0-9]{36}']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	token := jwtSourceFixture(fmt.Sprintf(`{"label":%q}`, key))
	fs := New(Options{Detector: detector(t), Rules: engine}).Findings(t.Context(), model.Item{Source: "code", Path: "prod.txt", Text: token})
	if len(jwtRuleFindings(fs, "owned-shadow")) != 0 {
		t.Fatal("template replaced a checksum-proven payload credential")
	}
	found := jwtRuleFindings(fs, "github_pat_classic")
	if len(found) != 1 || !strings.Contains(found[0].Stage, "checksum") {
		t.Fatal("checksum proof disappeared")
	}
}

func TestJWTRulesNestedEscapedContainersAndOccurrences(t *testing.T) {
	engine := ownedJWTRules(t, "owned-jwt")
	inner := jwtSourceFixture(`{"tenantScope":"owned","label":"` + ownedJWTValue + `"}`)
	for _, escaped := range []bool{false, true} {
		spelling := inner
		if escaped {
			spelling = `\u0065` + inner[1:]
		}
		outer := jwtSourceFixture(`{"first":"` + spelling + `","second":"` + spelling + `"}`)
		fs := New(Options{Detector: detector(t), Rules: engine, AllOccurrences: true}).Findings(t.Context(), model.Item{Source: "code", Path: "prod.txt", Text: outer})
		found := jwtRuleFindings(fs, "owned-jwt")
		if len(found) != 2 || found[0].ByteStart == found[1].ByteStart {
			t.Fatal("nested/escaped containers lost distinct source occurrences", escaped, len(found))
		}
		for _, f := range found {
			if len(f.Evidence) < 2 || f.ByteStart < 0 || f.ByteEnd > len(outer) || f.ByteStart >= f.ByteEnd {
				t.Fatal("nested proof escaped source")
			}
		}
	}
}

func TestJWTRulesLimitsPragmasAndDisabledEngine(t *testing.T) {
	engine := ownedJWTRules(t, "owned-jwt")
	token := jwtSourceFixture(`{"tenantScope":"owned","label":"` + ownedJWTValue + `","note":"# prowl:allow"}`)
	base := Options{Detector: detector(t), Rules: engine}
	for _, cap := range []int{0, 1, 2} {
		opts := base
		opts.matchLimit = cap
		coverage := model.NewCoverage()
		fs := New(opts).Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: "prod.txt", Text: token})
		if cap == 0 && len(jwtRuleFindings(fs, "owned-jwt")) != 1 {
			t.Fatal("claim manufactured a pragma")
		}
		if cap > 0 && model.NewResult(fs, coverage).Complete {
			t.Fatal("combined producer cap became a complete scan")
		}
	}
	base.Rules = nil
	if len(jwtRuleFindings(New(base).Findings(t.Context(), model.Item{Text: token}), "owned-jwt")) != 0 {
		t.Fatal("disabled templates still execute")
	}
	// JWE is an encrypted five-part container; claims are not available.
	if len(jwtRuleFindings(New(Options{Detector: detector(t), Rules: engine}).Findings(t.Context(), model.Item{Text: token + ".abc.def"}), "owned-jwt")) != 0 {
		t.Fatal("encrypted container interpreted as plaintext claims")
	}
}

func TestJWTRulesBundledOnlyTypeAndSelection(t *testing.T) {
	key := "AAAAQ7mR3vK:" + strings.Repeat("Q7mR3vK8pT2xN6cW4bY9", 7)
	token := jwtSourceFixture(fmt.Sprintf(`{"label":%q}`, key))
	engine, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	item := model.Item{Source: "code", Path: "prod.txt", Text: token}
	fs := New(Options{Detector: detector(t), Rules: engine}).Findings(t.Context(), item)
	found := jwtRuleFindings(fs, "firebase-fcm-server-key")
	if len(found) != 1 || found[0].Stage != "rule/jwt-payload" {
		t.Fatal("bundled-only JWT credential missing")
	}
	engine.Filter(rules.FilterOpts{ExcludeIDs: []string{"firebase-fcm-server-key"}})
	fs = New(Options{Detector: detector(t), Rules: engine}).Findings(t.Context(), item)
	if len(jwtRuleFindings(fs, "firebase-fcm-server-key")) != 0 {
		t.Fatal("filtered bundled rule executed inside JWT")
	}
	if len(jwtRuleFindings(New(Options{Detector: detector(t)}).Findings(t.Context(), item), "firebase-fcm-server-key")) != 0 {
		t.Fatal("template-only type leaked into builtins")
	}
}

func TestJWTRulesCompanionIsolationAndStandaloneVerification(t *testing.T) {
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(200) }))
	defer server.Close()
	for _, companion := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "verify.yaml")
		extract, header := "", ""
		if companion {
			extract, header = "extract:\n  account: 'tenant_[ab]'\n", "      X-Account: '{{account}}'\n"
		}
		text := "id: owned-jwt\nmatch: [owned-jwt]\n" + extract + "requests:\n  - method: GET\n    url: " + server.URL + "\n    headers:\n      Authorization: 'Bearer {{secret}}'\n" + header + "    matchers:\n      - type: status\n        status: [200]\n"
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, before := range []bool{false, true} {
			set, err := verify.Load(time.Second, path)
			if err != nil {
				t.Fatal(err)
			}
			calls = 0
			token := jwtSourceFixture(`{"tenantScope":"owned","account":"tenant_a","label":"` + ownedJWTValue + `"}`)
			coverage := model.NewCoverage()
			fs := New(Options{Detector: detector(t), Rules: ownedJWTRules(t, "owned-jwt"), Verifiers: set, VerifyAll: before}).Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: "prod.json", Text: fmt.Sprintf(`{"account":"tenant_b","token":%q}`, token)})
			found := jwtRuleFindings(fs, "owned-jwt")
			if len(found) != 1 {
				t.Fatal("verification lost payload-only rule")
			}
			if companion && (calls != 0 || found[0].Verified != nil || found[0].Verification == nil || found[0].Verification.Status != "error" || model.NewResult(fs, coverage).Complete) {
				t.Fatal("claims borrowed companion fields")
			}
			if !companion && (calls != 1 || found[0].Verified == nil || !*found[0].Verified) {
				t.Fatal("standalone rule credential could not be verified")
			}
		}
	}
}

func TestJWTRulesPublicAuditIsolation(t *testing.T) {
	calls := 0
	audit := auditFunc(func(_ context.Context, typ, value string, bindings map[string]string) *model.PublicKeyAudit {
		if typ == "gcp_api_key" {
			calls++
			if value != ownedJWTValue || len(bindings) != 0 {
				t.Fatal("payload-only template borrowed public resource bindings")
			}
		}
		return nil
	})
	token := jwtSourceFixture(`{"tenantScope":"owned","projectId":"inner-project","label":"` + ownedJWTValue + `"}`)
	fs := New(Options{Detector: detector(t), Rules: ownedJWTRules(t, "gcp_api_key"), PublicAuditor: audit}).Findings(t.Context(), model.Item{Source: "code", Path: "prod.json", Text: fmt.Sprintf(`{"projectId":"outer-project","token":%q}`, token)})
	if calls != 1 || len(jwtRuleFindings(fs, "gcp_api_key")) != 1 {
		t.Fatal("public audit lost payload rule")
	}
}

func TestJWTRulesEscapedWholeValueAndStructuralMatcher(t *testing.T) {
	const value = "OVAL_a\"b\\c\nDr4_END"
	path := filepath.Join(t.TempDir(), "owned.yaml")
	raw := `id: owned-whole
info:
  name: owned whole value
  severity: high
matchers:
  - type: regex
    regex: ['(?s)OVAL_.+?_END']
extractors:
  - type: regex
    regex: ['(?s)(OVAL_.+?_END)']
    group: 1
---
id: owned-structure
info:
  name: owned object structure
  severity: high
matchers:
  - type: regex
    regex: ['\{"kind":"owned","code":"(RAW_[A-Za-z0-9]{16})"\}']
extractors:
  - type: regex
    regex: ['\{"kind":"owned","code":"(RAW_[A-Za-z0-9]{16})"\}']
    group: 1
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{fmt.Sprintf(`{"label":%q}`, value), `{"kind":"owned","code":"RAW_Q7mR3vK8pT2xN6cW"}`} {
		token := jwtSourceFixture(payload)
		var records []mlscore.Record
		fs := New(Options{Detector: detector(t), Rules: engine, RevealSecrets: true, ML: publicRecordScorer{&records}}).Findings(t.Context(), model.Item{Source: "code", Path: "prod.txt", Text: token})
		typ, want := "owned-whole", value
		if strings.Contains(payload, "RAW_") {
			typ, want = "owned-structure", "RAW_Q7mR3vK8pT2xN6cW"
		}
		found := jwtRuleFindings(fs, typ)
		if len(found) != 1 || found[0].Redacted != want {
			t.Fatal("logical whole value or raw object matcher lost", typ, len(found))
		}
		if typ == "owned-whole" {
			ok := false
			for _, record := range records {
				ok = ok || record.Value == value && record.Context.Name == "label"
			}
			if !ok {
				t.Fatal("escaped credential identity was changed before ML")
			}
		}
	}
}

func FuzzJWTRulesKeepLogicalIdentityAndBoundedCoordinates(f *testing.F) {
	for _, note := range []string{"ordinary", "\n# prowl:allow", "quotes\"\\", "😀密码", "\xff"} {
		f.Add(note)
	}
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		f.Fatal(err)
	}
	p := New(Options{Detector: detect.New(tax), Rules: ownedJWTRules(f, "owned-jwt"), RevealSecrets: true, AllOccurrences: true})
	f.Fuzz(func(t *testing.T, note string) {
		if len(note) > 512 {
			return
		}
		payload, _ := json.Marshal(map[string]string{"tenantScope": note, "label": ownedJWTValue})
		token := jwtSourceFixture(string(payload))
		text := "note 🚀\nTOKEN=" + token
		fs := p.Findings(t.Context(), model.Item{Source: "code", Path: "prod.txt", Text: text})
		found := jwtRuleFindings(fs, "owned-jwt")
		if len(found) == 0 {
			t.Fatal("unrelated data hid payload template credential")
		}
		for _, hit := range found {
			if hit.ByteStart < 0 || hit.ByteStart >= hit.ByteEnd || hit.ByteEnd > len(text) || !strings.HasPrefix(hit.Redacted, "OWNED_") {
				t.Fatal("invalid logical value or source projection")
			}
		}
	})
}
