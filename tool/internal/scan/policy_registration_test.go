package scan

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

type registrationAuditor struct{ policies atomic.Int32 }

func (a *registrationAuditor) Audit(context.Context, string, string, map[string]string) *model.PublicKeyAudit {
	return nil
}

func (a *registrationAuditor) Policy() map[string]any {
	a.policies.Add(1)
	return map[string]any{"owned": "registration-test"}
}

func TestPolicyRegistrationSharedByWorkersAndBoundToCoverage(t *testing.T) {
	auditor := &registrationAuditor{}
	p := New(Options{Detector: detector(t), PublicAuditor: auditor, Workers: 4})
	coverage := model.NewCoverage()
	ctx := model.WithCoverage(context.Background(), coverage)
	items := make([]model.Item, 64)
	for i := range items {
		items[i] = model.Item{Path: "owned.env", Source: "code", Text: "ordinary text"}
	}
	if fs := p.Run(ctx, feed(items...)); len(fs) != 0 {
		t.Fatal("clean worker fixture produced findings")
	}
	if auditor.policies.Load() != 1 {
		t.Fatal("workers rehashed the same run's policy")
	}
	result := model.NewResult(nil, coverage)
	if result.Stats.Processed != 64 || !result.Complete {
		t.Fatal("policy registration changed processing counts or completeness")
	}
	registered := p.RegisterPolicy(ctx)
	before := auditor.policies.Load()
	p.Findings(registered, items[0])
	if auditor.policies.Load() != before {
		t.Fatal("registered context was not reused")
	}
	otherCoverage := model.NewCoverage()
	p.Findings(model.WithCoverage(registered, otherCoverage), items[0])
	if auditor.policies.Load() != before+1 || len(model.NewResult(nil, otherCoverage).Scope) == 0 {
		t.Fatal("a context marker hid policy registration from a new coverage ledger")
	}
	other := New(Options{Detector: detector(t), PublicAuditor: auditor})
	other.Findings(registered, items[0])
	if auditor.policies.Load() != before+2 {
		t.Fatal("a context marker hid another pipeline's policy")
	}
}

func TestPolicyRegistrationWithoutCoverageDoesNotCallExternalPolicy(t *testing.T) {
	auditor := &registrationAuditor{}
	p := New(Options{Detector: detector(t), PublicAuditor: auditor})
	p.Findings(context.Background(), model.Item{Path: "owned.env", Text: "ordinary text"})
	if auditor.policies.Load() != 0 {
		t.Fatal("a scan without a report ledger requested unused policy metadata")
	}
}
