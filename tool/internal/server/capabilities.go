package server

import (
	"context"
	"net/http"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/scan"
)

func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": "1.4", "request_fields": []string{"content", "source", "path"},
		"required_fields": []string{"content"}, "redacted": true,
		"stages": map[string]bool{"l1": true, "rules": s.eng != nil, "ml": false,
			"verification": false, "semantic": false, "reconstruction": false, "ocr": false},
	})
}

func (s *Server) registerScope(ctx context.Context, items []scanItem) {
	scan.RegisterDetectionPolicy(ctx)
	coverage := model.CoverageFrom(ctx)
	templates := []*rules.Template{}
	if s.eng != nil {
		templates = s.eng.Templates()
	}
	coverage.RegisterScope("rules", "", templates)
	for _, item := range items {
		coverage.RegisterScope("http-input", item.Path, map[string]string{"source": item.toModel().Source, "boundary": "caller-supplied content"})
	}
}
