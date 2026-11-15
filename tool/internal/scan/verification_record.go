package scan

import (
	"context"
	"time"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/verify"
)

// Keep original prepared spans even after findings are mapped to source coordinates.
type verificationCandidate struct {
	typ, value  string
	start, end  int
	jwtPayload  bool
	unboundView string
}

func unboundVerificationView(it model.Item) string {
	switch it.Meta["source_transform"] {
	case "mobile-printable-strings":
		return "derived mobile strings"
	case "web-state-decoded":
		return "decoded web state"
	}
	return ""
}

func (c verificationCandidate) apply(ctx context.Context, set *verify.Set, doc *literalDocument, original, path string, f *model.Finding) {
	if (c.jwtPayload || c.unboundView != "") && set != nil {
		f.Verified, f.Rationale, f.Verification = verificationResult(set.VerifyLiteral(ctx, c.typ, c.value, nil, detect.IsExampleOrPlaceholder(c.value)))
		noteVerificationFailure(ctx, path, f.Verification)
		return
	}
	f.Verified, f.Rationale, f.Verification = applyLiteralVerify(ctx, set, doc, c.typ, c.value, c.start, c.end, original)
	noteVerificationFailure(ctx, path, f.Verification)
}

func noteVerificationFailure(ctx context.Context, path string, detail *model.Verification) {
	if detail != nil && detail.Status == string(verify.Errored) {
		code := "verification_inconclusive"
		if detail.Reason == "structured literal could not be established" {
			code = "verification_unsafe_literal"
		}
		model.Note(ctx, code, path, true)
	}
}

func verificationMetadata(r verify.Result) *model.Verification {
	detail := &model.Verification{Status: string(r.Status), Verifier: r.Verifier, Capabilities: append([]string(nil), r.Access...)}
	if !r.CheckedAt.IsZero() {
		detail.CheckedAt = r.CheckedAt.UTC().Format(time.RFC3339Nano)
	}
	if r.Status == verify.Errored {
		detail.Reason = r.Note // Verifier transport errors are already classified, never raw URL errors.
	}
	return detail
}

func (c verificationCandidate) audit(ctx context.Context, auditor PublicAuditor, doc *literalDocument, bindings map[string]string, path string, f *model.Finding) {
	if !publicaudit.Supports(c.typ) {
		return
	}
	if c.unboundView != "" {
		doc, bindings = nil, nil
		if publicaudit.GoogleType(c.typ) {
			bindings = map[string]string{"firebaseConfig": c.unboundView}
		}
	}
	if c.jwtPayload {
		// Decoding claims does not establish a configuration/companion relationship.
		doc, bindings = nil, nil
	}
	if doc != nil {
		bindings = nil
		if !doc.verificationUnsafe {
			if v := doc.locate(c.start, c.end); v != nil && !doc.unsafeGroups[v.group] {
				bindings = doc.publicBindingsFor(v.group, doc.bindings[v.group])
			}
		}
	}
	if doc != nil && publicaudit.GoogleType(c.typ) {
		bindings = doc.firebaseAndroidBindings(ctx, path, c, bindings)
	}
	f.PublicKeyAudit = auditor.Audit(ctx, c.typ, c.value, bindings)
	if f.PublicKeyAudit == nil {
		return
	} // Inapplicable public-key candidates have no audit metadata.
	if f.PublicKeyAudit.Status == "inconclusive" {
		model.Note(ctx, "public_key_audit_inconclusive", path, true)
	}
}
