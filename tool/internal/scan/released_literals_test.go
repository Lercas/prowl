package scan

import (
	"context"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/verify"
)

// Adapt the released grammar fixtures to the immutable 1.5 Pipeline API. These
// fixtures test L1 semantics with a recording scorer; real L2 qualification is
// tracked separately and must not be inferred from the recording scorer.
func restoredFindings(ctx context.Context, det *detect.Detector, eng *rules.Engine, vset *verify.Set, it model.Item, allow func(string, string) bool, scorer mlscore.Scorer) []model.Finding {
	return New(Options{Detector: det, Rules: eng, Verifiers: vset, Allow: allow, ML: scorer}).Findings(ctx, it)
}
