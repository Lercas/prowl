// prowl-ml-corpus captures real pipeline contexts for annotated offline fixtures.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

type annotation struct {
	Name        string `json:"name"`
	Text        string `json:"text"`
	Path        string `json:"path"`
	Value       string `json:"value"`
	LabelBinary int    `json:"label_binary"`
	LabelType   string `json:"label_type"`
}

type capture struct{ records []mlscore.Record }

func (*capture) Local() bool        { return true }
func (*capture) Threshold() float64 { return .3 }
func (c *capture) Score(_ context.Context, records []mlscore.Record) ([]mlscore.Result, error) {
	c.records = append(c.records, records...)
	out := make([]mlscore.Result, len(records))
	for i := range out {
		out[i].Score = 1
	}
	return out, nil
}

func run(in io.Reader, out io.Writer) error {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		return err
	}
	if err := taxonomy.RequireComplete(tax); err != nil {
		return err
	}
	det := detect.New(tax)
	dec, enc := json.NewDecoder(in), json.NewEncoder(out)
	for row := 1; ; row++ {
		var a annotation
		if err := dec.Decode(&a); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("invalid annotated fixture %d", row)
		}
		if a.LabelBinary != 0 && a.LabelBinary != 1 || a.LabelType == "" || a.Value == "" {
			return fmt.Errorf("fixture %d has invalid labels", row)
		}
		if a.LabelBinary == 0 && !strings.HasPrefix(a.LabelType, "neg_") {
			return fmt.Errorf("fixture %d needs an explicit negative label", row)
		}
		scorer := &capture{}
		fs := scan.New(scan.Options{Detector: det, ML: scorer, RevealSecrets: true, IgnorePragmas: true}).Findings(context.Background(), model.Item{Source: "code", Path: a.Path, Text: a.Text})
		for _, f := range fs {
			if model.IsIncompleteFinding(f) {
				return fmt.Errorf("fixture %d is incomplete", row)
			}
		}
		if len(fs) == 0 && len(scorer.records) == 0 && a.LabelBinary == 0 {
			continue
		}
		if len(fs) != 1 || len(scorer.records) != 1 || scorer.records[0].Value != a.Value || fs[0].Redacted != a.Value {
			return fmt.Errorf("fixture %d does not identify exactly one annotated pipeline candidate", row)
		}
		if a.LabelBinary == 1 && fs[0].Type != a.LabelType {
			return fmt.Errorf("fixture %d does not match its annotated secret type", row)
		}
		if fs[0].ByteStart < 0 || fs[0].ByteEnd <= fs[0].ByteStart || fs[0].ByteEnd > len(a.Text) {
			return fmt.Errorf("fixture %d has invalid source bounds", row)
		}
		record := struct {
			Value       string          `json:"value"`
			Context     mlscore.Context `json:"context"`
			Text        string          `json:"text"`
			Span        [2]int          `json:"span"`
			LabelBinary int             `json:"label_binary"`
			LabelType   string          `json:"label_type"`
			Origin      string          `json:"origin"`
		}{a.Value, scorer.records[0].Context, a.Text, [2]int{utf8.RuneCountInString(a.Text[:fs[0].ByteStart]), utf8.RuneCountInString(a.Text[:fs[0].ByteEnd])}, a.LabelBinary, a.LabelType, "canonical-fixture:" + a.Name}
		if err := enc.Encode(record); err != nil {
			return fmt.Errorf("write fixture %d: %w", row, err)
		}
	}
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: prowl-ml-corpus < annotated-fixtures.jsonl > corpus.jsonl")
		os.Exit(2)
	}
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
