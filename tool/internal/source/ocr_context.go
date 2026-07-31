package source

import (
	"context"

	"github.com/Lercas/prowl/tool/internal/ocr"
)

type ocrContextKey struct{}

// WithOCR enables the optional OCR engine for every payload emitted under ctx, including archive,
// mail, PDF, filesystem, and Git-history members.
func WithOCR(ctx context.Context, engine *ocr.Engine) context.Context {
	if engine == nil {
		return ctx
	}
	return context.WithValue(ctx, ocrContextKey{}, engine)
}

func ocrEngine(ctx context.Context) *ocr.Engine {
	engine, _ := ctx.Value(ocrContextKey{}).(*ocr.Engine)
	return engine
}
