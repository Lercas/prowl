package scan

import (
	"context"
	"regexp"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestRawCandidateCapRemainsVisibleAfterDedupeAndAllowlist(t *testing.T) {
	defer detect.ApplyTuning(3.5, 4.2, 50000)
	detect.ApplyTuning(3.5, 4.2, 2)
	tax := &taxonomy.Taxonomy{Types: []taxonomy.SecretType{
		{ID: "owned_cap_first", Category: "cloud", RE: regexp.MustCompile(`OWNED_[A-Za-z0-9]{12}`)},
		{ID: "owned_cap_overlap", Category: "cloud", RE: regexp.MustCompile(`OWNED_[A-Za-z0-9]{12}`)},
		{ID: "owned_cap_late", Category: "cloud", RE: regexp.MustCompile(`LATE_[A-Za-z0-9]{12}`)},
	}}
	for _, allowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "dedupe", true: "allowlist"}[allowed], func(t *testing.T) {
			allow := func(value, _ string) bool { return allowed && value == "OWNED_G7hJ9kL2mN5p" }
			item := model.Item{Source: "file", Path: "owned.env", Text: "OWNED_G7hJ9kL2mN5p LATE_A6bC9dE2fG7h"}
			findings := Findings(context.Background(), detect.New(tax), nil, nil, item, allow, nil)
			markers := 0
			for _, f := range findings {
				if f.Type == ResultsTruncatedType {
					markers++
				}
			}
			if markers != 1 {
				t.Fatal("raw candidate cap was lost; omitted late secret was reported as a complete scan")
			}
		})
	}
}
