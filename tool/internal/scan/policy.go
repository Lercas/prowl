package scan

import (
	"context"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
)

// DetectionRevision changes when source interpretation or suppression semantics change.
const DetectionRevision = "1.5.0-base64-jwt-v1"

// Capabilities reports configured stages; request fields cannot change this snapshot.
func (p *Pipeline) Capabilities() (redacted bool, stages map[string]bool) {
	o := p.options
	stages = map[string]bool{
		"l1": o.Detector != nil, "rules": o.Rules != nil,
		"ml": o.ML != nil, "verification": o.Verifiers != nil,
		"reconstruction": o.Reconstruct, "semantic": o.Semantic, "ocr": false,
	}
	if o.PublicAuditor != nil {
		stages["public_key_audit"] = true
	}
	return !o.RevealSecrets, stages
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
		var err error
		taxonomy, err = o.Detector.PolicyDigest()
		if err != nil {
			c.Note("detection_policy_failed", "", true)
		}
	}
	_, stages := p.Capabilities()
	c.RegisterScope("detection_policy", "1.5.0", map[string]any{
		"revision": DetectionRevision, "taxonomy": taxonomy, "stages": stages,
		"verify_all": o.VerifyAll, "ignore_pragmas": o.IgnorePragmas, "allow_callback": o.Allow != nil,
		"all_occurrences": o.AllOccurrences,
	})
	if o.PublicAuditor != nil {
		var policy any = "structured-siblings-and-static-js-groups"
		if configured, ok := o.PublicAuditor.(interface{ Policy() map[string]any }); ok {
			policy = configured.Policy()
		}
		c.RegisterScope("public_key_audit", publicaudit.Revision, policy)
	}
	if o.Semantic && o.SemanticEngine != nil {
		c.RegisterScope("semantic", "literal-span-v1", o.SemanticEngine.Policy())
	}
	rulePolicy := ""
	if o.Rules != nil {
		var err error
		rulePolicy, err = o.Rules.PolicyDigest()
		if err != nil {
			c.Note("rules_policy_failed", "", true)
		}
	}
	c.RegisterScope("rules", "", rulePolicy)
}
