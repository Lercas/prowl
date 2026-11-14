package scan

import (
	"context"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/verify"
)

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
