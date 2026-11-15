package scan

import (
	"encoding/json"
	"fmt"
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/secretindex"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizedJWTTemplateAndBuiltinSourceContext(t *testing.T) {
	const password = "R7v!K9pX2mQ"
	token := jwtSourceFixture(fmt.Sprintf(`{"password":%q,"tenantScope":"owned","service_secret":%q}`, password, ownedJWTValue))
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	engine := ownedJWTRules(t, "owned-jwt")
	for _, chain := range []string{"escape", "hex-escape", "percent", "html", "concat", "charcode"} {
		blob := token
		blob, transform := normalizedPipelineJWT(blob, chain)
		for _, ext := range []string{"txt", "js", "json", "yaml", "toml"} {
			t.Run(fmt.Sprintf("%s-%s", ext, chain), func(t *testing.T) {
				text := "note 🚀\nblob='" + blob + "'"
				switch ext {
				case "js":
					text = "/*🚀*/ const blob='" + blob + "';"
				case "json":
					text = fmt.Sprintf(`{"note":"🚀","blob":%q}`, blob)
				case "yaml":
					text = "note: 🚀\nblob: '" + blob + "'"
				case "toml":
					text = "note='🚀'\nblob='" + blob + "'"
				}
				var rows []mlscore.Record
				coverage := model.NewCoverage()
				fs := New(Options{Detector: detector(t), Rules: engine, ML: publicRecordScorer{&rows}, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location}).Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: "prod." + ext, Text: text})
				for typ, value := range map[string]string{"generic_password": password, "owned-jwt": ownedJWTValue} {
					found := jwtRuleFindings(fs, typ)
					if len(found) != 1 {
						t.Fatal("wrapped payload candidate missing/duplicated", typ, len(found))
					}
					f := found[0]
					if f.ValueFingerprint != id.Fingerprint(value) || f.Context != nil || !strings.Contains(f.Stage, "jwt-payload") || f.ByteStart < strings.Index(text, blob) || f.ByteEnd > strings.Index(text, blob)+len(blob) {
						t.Fatal("logical identity or source was lost")
					}
					proofs := 0
					for _, e := range f.Evidence {
						if e.Start < 0 || e.Start >= e.End || e.End > len(text) {
							t.Fatal("proof escaped physical source")
						}
						if e.Transform == transform || strings.HasPrefix(e.Transform, "base64-decode") {
							if proofs == 0 && e.Transform != transform {
								t.Fatal("normalization proof out of order")
							}
							proofs++
						}
					}
					if proofs != 2 {
						t.Fatal("normalization/payload steps missing", proofs)
					}
				}
				if !model.NewResult(fs, coverage).Complete {
					t.Fatal("bounded wrapper became incomplete")
				}
				seen := map[string]string{}
				for _, row := range rows {
					seen[row.Value] = row.Context.Name
				}
				if seen[password] != "password" || seen[ownedJWTValue] != "service_secret" {
					t.Fatal("ML got outer wrapper context")
				}
				raw, _ := json.Marshal(fs)
				for _, value := range []string{password, ownedJWTValue, token, blob} {
					if strings.Contains(string(raw), value) {
						t.Fatal("credential leaked in default report")
					}
				}
			})
		}
	}
}
func TestNormalizedJWTDisabledContainerCannotBorrowCompanions(t *testing.T) {
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(200) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "verify.yaml")
	if err := os.WriteFile(path, []byte("id: owned-aws\nmatch: [aws_access_key_id]\nextract:\n  account: 'tenant_[ab]'\nrequests:\n  - url: "+server.URL+"\n    headers:\n      X-Account: '{{account}}'\n    matchers:\n      - type: status\n        status: [200]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	var types []taxonomy.SecretType
	for _, st := range tax.Types {
		if st.ID != "jwt" {
			types = append(types, st)
		}
	}
	blob, _ := normalizedPipelineJWT(jwtSourceFixture(`{"access_key":"AKIANAFGYOEYPXU1DSYP","account":"tenant_a"}`), "percent")
	for _, before := range []bool{false, true} {
		set, err := verify.Load(time.Second, path)
		if err != nil {
			t.Fatal(err)
		}
		coverage := model.NewCoverage()
		fs := New(Options{Detector: detect.New(&taxonomy.Taxonomy{Types: types}), Verifiers: set, VerifyAll: before}).Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: "prod.json", Text: fmt.Sprintf(`{"account":"tenant_b","blob":%q}`, blob)})
		found := jwtRuleFindings(fs, "aws_access_key_id")
		if len(found) != 1 || calls != 0 || found[0].Verified != nil || found[0].Verification == nil || found[0].Verification.Status != "error" || model.NewResult(fs, coverage).Complete {
			t.Fatal("decoded duplicate borrowed a companion", before, calls)
		}
	}
}

func TestNormalizedJWTDisabledContainerRedactsPrivateMetadataWithoutRules(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	var types []taxonomy.SecretType
	for _, st := range tax.Types {
		if st.ID != "jwt" {
			types = append(types, st)
		}
	}
	token := jwtSourceFixture(`{"password":"R7v!K9pX2mQ"}`)
	blob, _ := normalizedPipelineJWT(token, "percent")
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	fs := New(Options{Detector: detect.New(&taxonomy.Taxonomy{Types: types}), ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location}).Findings(t.Context(), model.Item{Source: "code", Path: "folder/" + token + "/prod.txt", Text: blob})
	if len(jwtRuleFindings(fs, "generic_password")) != 1 {
		t.Fatal("disabled JWT output hid indexed password")
	}
	for _, f := range fs {
		if strings.Contains(f.IndexPath, token) || strings.Contains(f.IndexSource, token) || strings.Contains(f.IndexType, token) {
			t.Fatal("logical container remained in private metadata")
		}
	}
}

func normalizedPipelineJWT(token, kind string) (string, string) {
	switch kind {
	case "escape":
		return `\u0065` + token[1:], "text-normalize"
	case "hex-escape":
		return `\x65` + token[1:], "text-normalize"
	case "percent":
		return strings.ReplaceAll(token, ".", "%2E"), "percent-html-decode"
	case "html":
		return strings.ReplaceAll(token, ".", "&#46;"), "percent-html-decode"
	case "concat":
		return token[:18] + `" + "` + token[18:], "text-normalize"
	case "charcode":
		args := make([]string, len(token))
		for i := range token {
			args[i] = fmt.Sprint(token[i])
		}
		return "String.fromCharCode(" + strings.Join(args, ",") + ")", "charcode-decode"
	}
	return token, ""
}
