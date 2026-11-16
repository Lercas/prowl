package server

import (
	"context"
	"net/http"

	"github.com/Lercas/prowl/tool/internal/model"
)

func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	redacted, stages := s.pipeline.Capabilities()
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": "1.4", "request_fields": []string{"content", "source", "path"},
		"required_fields": []string{"content"}, "redacted": redacted, "stages": stages,
	})
}

func (s *Server) registerScope(ctx context.Context, items []scanItem) context.Context {
	ctx = s.pipeline.RegisterPolicy(ctx)
	for _, item := range items {
		model.CoverageFrom(ctx).RegisterScope("http-input", item.Path, map[string]string{
			"source": item.toModel().Source, "boundary": "caller-supplied content",
		})
	}
	return ctx
}
