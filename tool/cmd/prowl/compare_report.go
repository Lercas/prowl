package main

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/model"
)

type comparisonReport struct {
	SchemaVersion      string          `json:"schema_version"`
	Complete           bool            `json:"complete"`
	Before             int             `json:"before"`
	After              int             `json:"after"`
	Suppressed         int             `json:"suppressed"`
	SuppressionPercent float64         `json:"suppression_percent"`
	Deduplicated       bool            `json:"deduplicated"`
	SecretsRevealed    bool            `json:"secrets_revealed"`
	Raw                []model.Finding `json:"raw"`
	Kept               []model.Finding `json:"kept"`
}

func writeComparison(ctx context.Context, c commonFlags, raw, kept []model.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	write := func(w io.Writer) error {
		if c.format == "pretty" {
			_, err := io.WriteString(w, formatCompare(raw, kept))
			return err
		}
		if raw == nil {
			raw = []model.Finding{}
		}
		if kept == nil {
			kept = []model.Finding{}
		}
		percent := 0.0
		if len(raw) > 0 {
			percent = 100 * float64(len(raw)-len(kept)) / float64(len(raw))
		}
		return json.NewEncoder(w).Encode(comparisonReport{"1.5.0-compare-v1", true, len(raw), len(kept), len(raw) - len(kept), percent, c.dedupe, c.showSecrets, raw, kept})
	}
	if c.output != "" {
		return localfile.WriteAtomicContext(ctx, c.output, 0600, write)
	}
	if c.silence && c.format == "pretty" {
		return nil
	}
	return write(os.Stdout)
}

func writeComparisonFailure(c commonFlags) {
	if c.format == "json" && c.output == "" {
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			SchemaVersion string `json:"schema_version"`
			Complete      bool   `json:"complete"`
			Error         string `json:"error"`
		}{"1.5.0-compare-v1", false, "comparison could not complete"})
	}
}
