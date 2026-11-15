package scan

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/reconstruct"
	"github.com/Lercas/prowl/tool/internal/rules"
)

func TestPublicBindingsAreItemLocalInSharedPipeline(t *testing.T) {
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	auditor := auditFunc(func(_ context.Context, _ string, key string, bindings map[string]string) *model.PublicKeyAudit {
		var id int
		_, err := fmt.Sscanf(key[len(key)-2:], "%x", &id)
		if err != nil || bindings["app_id"] != fmt.Sprintf("ABCDEF%04d", id) {
			t.Error("cross-item companion contamination")
		}
		return &model.PublicKeyAudit{Provider: "algolia", Status: "search_only"}
	})
	p := New(Options{Detector: detector(t), Rules: engine, PublicAuditor: auditor})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			key := auditTestKey[:30] + fmt.Sprintf("%02x", i)
			text := fmt.Sprintf(`const c={app_id:"ABCDEF%04d",algolia_api_key:"%s"};`, i, key)
			fs := p.Findings(t.Context(), model.Item{Source: "code", Path: "prod.js", Text: text})
			if len(fs) != 1 || fs[0].PublicKeyAudit == nil || fs[0].Verified != nil {
				t.Error("item lost isolated public audit")
			}
		})
	}
	wg.Wait()
	if p.options.publicBindings != nil {
		t.Fatal("shared pipeline retained source bindings")
	}
}

func TestPublicBindingsRetainOriginalReconstructionSpan(t *testing.T) {
	source := `const c={app_id:"ABCDEF1234",algolia_api_key:"` + auditTestKey + `"+""};`
	start := strings.Index(source, `"`+auditTestKey)
	end := strings.LastIndex(source, "}")
	b := &publicBindings{text: source}
	c := verificationCandidate{typ: "algolia-api-key", value: auditTestKey, start: 0, end: len(auditTestKey)}
	origin := &reconstructionOrigin{value: reconstruct.Value{Expression: reconstruct.Span{Start: start, End: end}}}
	got := b.forCandidate(t.Context(), c, origin)
	if got["app_id"] != "ABCDEF1234" {
		t.Fatal("used generated coordinates instead of original expression", got)
	}
	if b.forCandidate(t.Context(), c, nil) != nil {
		t.Fatal("synthetic offsets acquired a source companion")
	}
}

func TestPublicBindingsSuppressionPreventsAuditing(t *testing.T) {
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, pragmas := range []bool{false, true} {
		opts := Options{Detector: detector(t), Rules: engine, PublicAuditor: auditFunc(func(context.Context, string, string, map[string]string) *model.PublicKeyAudit {
			t.Error("suppressed key reached auditor")
			return nil
		})}
		text := `const c={app_id:"ABCDEF1234",algolia_api_key:"` + auditTestKey + `"};`
		if pragmas {
			text += " // prowl:allow"
		} else {
			opts.Allow = func(string, string) bool { return true }
		}
		fs := New(opts).Findings(t.Context(), model.Item{Source: "code", Path: "prod.js", Text: text})
		if len(fs) != 0 {
			t.Fatal("suppression changed", fs)
		}
	}
}
