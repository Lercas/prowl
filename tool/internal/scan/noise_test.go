package scan

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

func TestNoiseCorpusDefaultAndML(t *testing.T) {
	testNoiseCorpus(t, "testdata/noise-1.4.0.json")
}

func TestDeepNoiseCorpusDefaultAndML(t *testing.T) {
	testNoiseCorpus(t, "testdata/noise-deep-1.4.0.json")
}

func testNoiseCorpus(t *testing.T, filename string) {
	t.Helper()
	var cases []struct {
		Name, Path, Text, Truth, Value string
		Types                          []string
		MLExpected                     bool `json:"ml_expected"`
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	if eng.Len() != 175 {
		t.Fatalf("bundled inventory changed: %d", eng.Len())
	}
	t.Setenv("PROWL_HOME", t.TempDir())
	ml, err := mlscore.NewEmbedded(.5, "")
	if err != nil {
		t.Fatal(err)
	}
	det := detector(t)
	for _, useML := range []bool{false, true} {
		var scorer mlscore.Scorer
		if useML {
			scorer = ml
		}
		for _, c := range cases {
			t.Run(c.Name+map[bool]string{false: "/default", true: "/ml"}[useML], func(t *testing.T) {
				fs := Findings(context.Background(), det, eng, nil, model.Item{Path: c.Path, Text: c.Text, Source: "code"}, nil, scorer)
				if c.Truth == "negative" {
					if len(fs) != 0 {
						t.Fatalf("non-secret source produced %d findings, first type %s", len(fs), fs[0].Type)
					}
					return
				}
				if useML && !c.MLExpected {
					return
				}
				for _, f := range fs {
					if f.Fingerprint != model.ComputeFingerprint(f.Type, c.Path, c.Value) {
						continue
					}
					for _, typ := range c.Types {
						if typ == f.Type {
							return
						}
					}
				}
				t.Fatalf("literal credential missing or misclassified, expected types %v", c.Types)
			})
		}
	}
}

func TestMLContextBelongsToCandidate(t *testing.T) {
	const value = "Kp9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7sL"
	text := `const password="not-a-credential";` + strings.Repeat(`const x=0;`, 2000) + `const api_key="` + value + `";`
	start := strings.Index(text, value)
	it := model.Item{Text: text, Path: "app.js", Source: "code"}
	r := recordFor(value, it, start)
	if r.Context.Name != "api_key" || len(r.Context.Line) > 400 || !strings.Contains(r.Context.Line, value) || strings.Contains(r.Context.Line, "not-a-credential") {
		t.Fatalf("ML received context from another binding: name=%q, bytes=%d", r.Context.Name, len(r.Context.Line))
	}
	old := revealSecrets.Load()
	SetRevealSecrets(true)
	t.Cleanup(func() { SetRevealSecrets(old) })
	ctx := revealContext(it, start)
	if ctx.Name != r.Context.Name || ctx.Line != r.Context.Line {
		t.Fatal("feedback and scoring contexts differ")
	}
}

func TestUnquotedLiteralDependsOnLanguageAndComments(t *testing.T) {
	const value = "Kp9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7sL"
	for _, path := range []string{"app.js", "app.ts", "app.py", "src.go"} {
		for _, text := range []string{"api_key = " + value, "password = passwordInput2"} {
			fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Path: path, Text: text, Source: "code"}, nil, nil)
			if len(fs) > 0 {
				t.Fatalf("identifier expression reported as secret in %s", path)
			}
		}
	}
	for _, c := range []struct{ path, text string }{
		{"config.env", "api_key=" + value}, {"config.yaml", "api_key: " + value},
		{"script.sh", "API_KEY=" + value}, {"app.py", "# api_key=" + value},
		{"app.js", `const api_key="` + value + `";`},
	} {
		fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Path: c.path, Text: c.text, Source: "code"}, nil, nil)
		if len(fs) == 0 {
			t.Fatalf("literal lost in %s", c.path)
		}
	}
}

func TestMLEvidenceDoesNotProtectContextualOrSemanticGuesses(t *testing.T) {
	for _, c := range []struct{ typ, stage, name, value string }{
		{"generic_password", "L1-context-pw", "password", "hunter2abc99"},
		{"generic_password", "semantic-candidate", "password", "hunter2abc99"},
		{"together-api-key", "rule", "together_checksum", "abcdef"},
		{"linode-api-token", "rule", "linode_id", "abcdef"},
		{"netlify-access-token", "rule", "value", "nfp_too_short"},
	} {
		if mlAnchoredEvidence(model.Finding{Type: c.typ, Stage: c.stage}, mlscore.Record{Value: c.value, Context: mlscore.Context{Name: c.name}}) {
			t.Fatalf("weak evidence bypassed ML: %s/%s/%s", c.typ, c.stage, c.name)
		}
	}
}

func TestMultilineAndMultilingualWeakPasswordsSurviveML(t *testing.T) {
	t.Setenv("PROWL_HOME", t.TempDir())
	ml, err := mlscore.NewEmbedded(.5, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"{\"password\":\n\"required\"}",
		`{"пароль":"required"}`, `{"contraseña":"required"}`, `PASS="required"`,
	} {
		fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Path: "config.json", Text: text, Source: "code"}, nil, ml)
		if len(fs) == 0 || fs[0].Type != "generic_password" {
			t.Fatal("literal weak password lost with a multiline or multilingual binding")
		}
		if fs[0].Verified != nil && *fs[0].Verified {
			t.Fatal("retaining an ML candidate claimed live verification")
		}
	}
}

func TestDetectionPolicyIsPresentForEmptyAndDirectScans(t *testing.T) {
	for _, empty := range []bool{true, false} {
		cov := model.NewCoverage()
		ctx := model.WithCoverage(context.Background(), cov)
		if empty {
			Run(ctx, feed(), detector(t), nil, nil, 1, nil, nil)
		} else {
			Findings(ctx, detector(t), nil, nil, model.Item{Text: "clean", Path: "config.env"}, nil, nil)
		}
		r := model.NewResult(nil, cov)
		found := false
		for _, scope := range r.Scope {
			if scope.Kind == "detection_policy" && scope.Target == "1.4.0" && scope.Policy != "" {
				found = true
			}
		}
		if !found {
			t.Fatal("detection heuristic revision missing from scope")
		}
	}
}
