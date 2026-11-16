package scan

import (
	"context"
	"encoding/hex"

	"github.com/Lercas/prowl/tool/internal/mlscore"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/reconstruct"
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
	if o.Reconstruct {
		policy["reconstruction_revision"] = reconstruct.Revision
	}
	if o.CrossFile {
		policy["cross_file"] = componentYAMLRevision
	}
	if o.configError {
		c.Note("configuration_policy_failed", "", true)
	}
	if o.configPolicy != nil {
		c.RegisterScope("detector_config", "", map[string]string{"revision": "loaded-config-v1", "digest": o.configPolicy.PolicyID()})
		if o.configPolicy.Restrictive() {
			c.Filtered()
		}
	} else if o.Allow != nil {
		c.RegisterScope("unversioned_policy", "allow", "unidentified-allow-callback-v1")
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
	if o.ML != nil {
		threshold := o.ML.Threshold()
		var id string
		if versioned, ok := o.ML.(interface{ PolicyID() string }); ok {
			id = versioned.PolicyID()
		}
		validID := false
		if len(id) == 64 {
			_, err := hex.DecodeString(id)
			validID = err == nil
		}
		kind := "ml_model"
		var thresholdPolicy any = threshold
		if !mlscore.ValidScore(threshold) {
			thresholdPolicy = "invalid"
		}
		if !validID || !mlscore.ValidScore(threshold) {
			kind = "unversioned_policy"
			id = ""
		}
		c.RegisterScope(kind, "ml", map[string]any{"revision": "loaded-model-v1", "digest": id, "threshold": thresholdPolicy, "local": o.ML.Local()})
	}
	if o.Verifiers != nil {
		digest, err := o.Verifiers.PolicyDigest()
		if err != nil {
			c.Note("verifier_policy_failed", "", true)
		}
		c.RegisterScope("verifiers", "", map[string]string{"revision": "loaded-verifiers-v1", "digest": digest})
	}
	c.RegisterScope("rules", "", rulePolicy)
	return context.WithValue(ctx, policyRegistrationKey{}, policyRegistration{p, c})
}
