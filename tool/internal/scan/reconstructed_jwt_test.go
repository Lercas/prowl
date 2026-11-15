package scan

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/secretindex"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func reconstructedJWTExpressions(token string) map[string]string {
	return map[string]string{
		"concat": "head+'" + token[12:] + "'",
		"array":  "[head,'" + token[12:] + "'].join('')",
		"atob":   "atob('" + base64.StdEncoding.EncodeToString([]byte(token)) + "')",
		"uri":    "decodeURIComponent('" + strings.ReplaceAll(url.PathEscape(token), ".", "%2E") + "')",
	}
}

func TestReconstructedJWTPayloadKeepsPasswordAndSourceProof(t *testing.T) {
	const password = "R7v!K9pX2mQ"
	const aws = "AKIANAFGYOEYPXU1DSYP"
	token := jwtSourceFixture(fmt.Sprintf(`{"access_key":%q,"password":%q,"tenantScope":"owned","service_secret":%q}`, aws, password, ownedJWTValue))
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	for name, expression := range reconstructedJWTExpressions(token) {
		for _, ext := range []string{"js", "tsx"} {
			t.Run(name+"-"+ext, func(t *testing.T) {
				text := "const head='" + token[:12] + "';\n/*🚀*/ const token=" + expression + ";\n"
				start := strings.Index(text, expression)
				var records []mlscore.Record
				coverage := model.NewCoverage()
				p := New(Options{Detector: detector(t), Rules: ownedJWTRules(t, "owned-jwt"), Reconstruct: true, ML: publicRecordScorer{&records}, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
				path := "bundle." + ext
				fs := p.Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: path, Text: text})
				found := map[string]bool{}
				for _, f := range fs {
					if !strings.HasPrefix(f.Stage, "reconstructed/") || !strings.Contains(f.Stage, "jwt-payload") {
						continue
					}
					for _, value := range []string{password, aws, ownedJWTValue} {
						if f.ValueFingerprint == id.Fingerprint(value) {
							found[value] = true
						}
					}
					if f.ByteStart != start || f.ByteEnd != start+len(expression) || f.Context != nil || f.Line != 2 || f.UTF16Col != newLineIndex(text).utf16Col(start) {
						t.Fatal("reconstructed JWT reported virtual coordinates")
					}
					if f.IndexLocationID != id.Location("code", path, f.Line, f.Col) {
						t.Fatal("index kept virtual JWT location")
					}
					steps := 0
					for _, e := range f.Evidence {
						if e.Start < 0 || e.Start >= e.End || e.End > len(text) {
							t.Fatal("evidence outside source")
						}
						if strings.Contains(e.Transform, "base64-decode") {
							steps++
							if e.Start != start || e.End != start+len(expression) || !strings.HasPrefix(e.Transform, "reconstructed/") || e.Path != path || e.Line != 2 {
								t.Fatal("payload evidence still refers to virtual Base64 bytes")
							}
						}
					}
					if steps == 0 {
						t.Fatal("payload transform proof was discarded")
					}
				}
				if len(found) != 3 || !model.NewResult(fs, coverage).Complete {
					t.Fatal("reconstructed JWT lost payload credentials", len(found))
				}
				raw, _ := json.Marshal(fs)
				for _, value := range []string{password, aws, ownedJWTValue, token} {
					if strings.Contains(string(raw), value) {
						t.Fatal("default output disclosed a reconstructed credential")
					}
				}
				scored := false
				for _, r := range records {
					scored = scored || r.Value == password && r.Context.Name == "password"
				}
				if !scored {
					t.Fatal("reconstructed password bypassed ML or lost logical context")
				}
			})
		}
	}
}

func TestReconstructedJWTDoesNotRelaxUnprovenCodeValues(t *testing.T) {
	token := jwtSourceFixture(`{"password":"R7v!K9pX2mQ"}`)
	for _, enabled := range []bool{false, true} {
		for _, quoted := range []bool{false, true} {
			text := "const token=" + token + ";"
			if quoted {
				text = "const token='" + token + "';"
			}
			fs := New(Options{Detector: detector(t), Reconstruct: enabled}).Findings(t.Context(), model.Item{Source: "code", Path: "bundle.js", Text: text})
			passwords := jwtRuleFindings(fs, "generic_password")
			if quoted && len(passwords) != 1 || !quoted && len(passwords) != 0 {
				t.Fatal("original literal/code boundary changed", enabled, quoted, len(passwords))
			}
		}
	}
}

func TestReconstructedJWTPayloadObserverSeesOriginalProofBeforeML(t *testing.T) {
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(401) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "verify.yaml")
	if err := os.WriteFile(path, []byte("id: owned-jwt\nmatch: [owned-jwt]\nrequests:\n  - url: "+server.URL+"\n    headers:\n      Authorization: 'Bearer {{secret}}'\n    matchers:\n      - type: status\n        status: [200]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := verify.Load(time.Second, path)
	if err != nil {
		t.Fatal(err)
	}
	token := jwtSourceFixture(fmt.Sprintf(`{"tenantScope":"owned","service_secret":%q}`, ownedJWTValue))
	expression := reconstructedJWTExpressions(token)["atob"]
	text := "/*🚀*/ const token=" + expression + ";"
	start := strings.Index(text, expression)
	var observed []model.Finding
	var beforeML []model.Finding
	scorer := &compareTestScorer{action: func(rows []mlscore.Record) ([]mlscore.Result, error) { return make([]mlscore.Result, len(rows)), nil }}
	location := func(_, _ string, line, col int) string { return fmt.Sprintf("loc:%d:%d", line, col) }
	fs := New(Options{Detector: detector(t), Rules: ownedJWTRules(t, "owned-jwt"), Reconstruct: true, Verifiers: set, ML: scorer, ValueFingerprint: func(string) string { return "keyed" }, LocationFingerprint: location, ObserveVerification: func(f model.Finding) { observed = append(observed, f) }, beforeML: func(fs []model.Finding) bool { beforeML = append(beforeML, fs...); return true }}).Findings(t.Context(), model.Item{Source: "code", Path: "bundle.js", Text: text})
	if len(jwtRuleFindings(fs, "owned-jwt")) != 0 || calls != 1 {
		t.Fatal("verification order or ML suppression changed", calls)
	}
	count := 0
	for _, f := range observed {
		if f.Type != "owned-jwt" {
			continue
		}
		line, col := newLineIndex(text).cols(start)
		// General Base64 traversal can observe the same value independently of
		// JavaScript reconstruction, at its distinct encoded source location.
		if f.IndexLocationID != location("code", "bundle.js", line, col) {
			continue
		}
		count++
		if f.Line != line || f.Col != col || f.IndexLocationID != location("code", "bundle.js", line, col) || f.Verified == nil || *f.Verified {
			t.Fatal("pre-ML observation lost source or rejected verdict")
		}
		if len(f.Evidence) != 0 {
			t.Fatal("private observation unexpectedly retained report evidence")
		}
	}
	if count != 1 {
		t.Fatal("payload rule observation missing")
	}
	count = 0
	for _, f := range beforeML {
		if f.Type != "owned-jwt" || !strings.HasPrefix(f.Stage, "reconstructed/") {
			continue
		}
		count++
		if f.ByteStart != start || f.ByteEnd != start+len(expression) {
			t.Fatal("pre-ML report kept virtual coordinates")
		}
		for _, e := range f.Evidence {
			if strings.Contains(e.Transform, "base64-decode") && (e.Start != start || e.End != start+len(expression) || !strings.HasPrefix(e.Transform, "reconstructed/")) {
				t.Fatal("observer recorded a virtual payload proof")
			}
		}
	}
	if count != 1 {
		t.Fatal("pre-ML report missing")
	}
}

func TestReconstructedJWTOptInAndDecoderShadowing(t *testing.T) {
	token := jwtSourceFixture(`{"password":"R7v!K9pX2mQ"}`)
	expression := reconstructedJWTExpressions(token)["atob"]
	for _, fixture := range []struct {
		enabled    bool
		path, text string
	}{
		{false, "bundle.js", "const token=" + expression + ";"},
		{true, "bundle.txt", "const token=" + expression + ";"},
		{true, "bundle.js", "function atob(x) { return x; }\nconst token=" + expression + ";"},
	} {
		fs := New(Options{Detector: detector(t), Reconstruct: fixture.enabled}).Findings(t.Context(), model.Item{Source: "code", Path: fixture.path, Text: fixture.text})
		for _, f := range fs {
			if strings.HasPrefix(f.Stage, "reconstructed/") {
				t.Fatal("unproven string gained a reconstructed finding")
			}
		}
	}
}

func FuzzReconstructedJWTPayloadOriginalCoordinates(f *testing.F) {
	for i, note := range []string{"ordinary", "🚀密码", "quotes\"\\\n", "# prowl:allow"} {
		f.Add(note, uint8(i))
	}
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		f.Fatal(err)
	}
	p := New(Options{Detector: detect.New(tax), Reconstruct: true})
	token := jwtSourceFixture(`{"password":"R7v!K9pX2mQ"}`)
	expressions := reconstructedJWTExpressions(token)
	kinds := []string{"concat", "array", "atob", "uri"}
	f.Fuzz(func(t *testing.T, note string, mode uint8) {
		if len(note) > 512 {
			return
		}
		quoted, _ := json.Marshal(note)
		prefix := "const note=" + string(quoted) + ";\nconst head='" + token[:12] + "';\n/*🚀*/ const token="
		expression := expressions[kinds[int(mode)%len(kinds)]]
		text := prefix + expression + ";"
		fs := p.Findings(t.Context(), model.Item{Source: "code", Path: "bundle.js", Text: text})
		found := false
		for _, hit := range fs {
			if hit.Type != "generic_password" || !strings.HasPrefix(hit.Stage, "reconstructed/") || !strings.Contains(hit.Stage, "jwt-payload") || hit.ByteStart != len(prefix) {
				continue
			}
			found = true
			if hit.ByteEnd != len(prefix)+len(expression) {
				t.Fatal("virtual source extent")
			}
			for _, e := range hit.Evidence {
				if e.Start < 0 || e.Start >= e.End || e.End > len(text) {
					t.Fatal("source proof out of bounds")
				}
				if strings.Contains(e.Transform, "base64-decode") && (e.Start != len(prefix) || e.End != len(prefix)+len(expression) || !strings.HasPrefix(e.Transform, "reconstructed/")) {
					t.Fatal("payload proof retained virtual source")
				}
			}
		}
		if !found {
			t.Fatal("unrelated literal hid reconstructed JWT password")
		}
	})
}
