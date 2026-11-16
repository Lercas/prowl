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
// Callers explicitly supply either the real embedded model or a recording scorer;
// recording-scorer results alone do not establish L2 qualification.
func restoredFindings(ctx context.Context, det *detect.Detector, eng *rules.Engine, vset *verify.Set, it model.Item, allow func(string, string) bool, scorer mlscore.Scorer) []model.Finding {
	return New(Options{Detector: det, Rules: eng, Verifiers: vset, Allow: allow, ML: scorer}).Findings(ctx, it)
}
