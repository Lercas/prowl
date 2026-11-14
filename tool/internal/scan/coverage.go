package scan

import "github.com/Lercas/prowl/tool/internal/model"

func hasIncompleteFinding(findings []model.Finding) bool {
	for _, f := range findings {
		if model.IsIncompleteFinding(f) {
			return true
		}
	}
	return false
}
