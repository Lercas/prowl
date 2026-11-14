package scan

import (
	"context"

	"github.com/Lercas/prowl/tool/internal/model"
)

// Capabilities reports configured stages; request fields cannot change this snapshot.
func (p *Pipeline) Capabilities() (redacted bool, stages map[string]bool) {
	o := p.options
	return !o.RevealSecrets, map[string]bool{
		"l1": o.Detector != nil, "rules": o.Rules != nil,
		"ml": o.ML != nil, "verification": o.Verifiers != nil,
		"reconstruction": o.Reconstruct, "semantic": false, "ocr": false,
	}
}

// RegisterPolicy stamps even empty HTTP batches with their configured detection profile.
// Arbitrary callback and external service contents are not immutable revision evidence.
func (p *Pipeline) RegisterPolicy(ctx context.Context) {
	c := model.CoverageFrom(ctx)
	o := p.options
	c.SetIdentityScope(o.IdentityKey)
	if o.RevealSecrets {
		c.RevealSecrets()
	}
	taxonomy := ""
	if o.Detector != nil {
		taxonomy = o.Detector.PolicyDigest()
	}
	_, stages := p.Capabilities()
	c.RegisterScope("detection_policy", "1.5.0", map[string]any{
		"revision": "literals-go-v2", "taxonomy": taxonomy, "stages": stages,
		"verify_all": o.VerifyAll, "ignore_pragmas": o.IgnorePragmas, "allow_callback": o.Allow != nil,
	})
	rulePolicy := ""
	if o.Rules != nil {
		rulePolicy = o.Rules.PolicyDigest()
	}
	c.RegisterScope("rules", "", rulePolicy)
}
