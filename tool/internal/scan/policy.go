package scan

import (
	"context"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
)

// DetectionRevision changes when source interpretation or suppression semantics change.
const DetectionRevision = "1.5.0-released-ml-evidence-v1"

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
	if o.CrossFile {
		stages["cross_file"] = true
	}
	return !o.RevealSecrets, stages
}

type policyRegistrationKey struct{}

type policyRegistration struct {
	pipeline *Pipeline
	coverage *model.Coverage
}

// RegisterPolicy stamps even empty scans with their configured detection profile.
// The returned context shares the registration with workers, avoiding per-item hashing.
// Arbitrary callback and external service contents are not immutable revision evidence.
func (p *Pipeline) RegisterPolicy(ctx context.Context) context.Context {
	c := model.CoverageFrom(ctx)
	if c == nil {
		return ctx
	}
	if registered, ok := ctx.Value(policyRegistrationKey{}).(policyRegistration); ok && registered.pipeline == p && registered.coverage == c {
		return ctx
	}
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
	policy := map[string]any{
		"revision": DetectionRevision, "taxonomy": taxonomy, "stages": stages,
		"verify_all": o.VerifyAll, "ignore_pragmas": o.IgnorePragmas, "allow_callback": o.Allow != nil,
		"all_occurrences": o.AllOccurrences,
	}
	if o.CrossFile {
		policy["cross_file"] = componentYAMLRevision
	}
	c.RegisterScope("detection_policy", "1.5.0", policy)
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
	return context.WithValue(ctx, policyRegistrationKey{}, policyRegistration{p, c})
}
