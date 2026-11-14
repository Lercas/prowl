package main

import (
	"testing"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
)

func TestReconstructionFlagReachesPreparedPipeline(t *testing.T) {
	for _, c := range []struct {
		args []string
		want int
	}{
		{nil, 0}, {[]string{"--reconstruct"}, 1}, {[]string{"--reconstruct=false"}, 0},
	} {
		flags, _, err := parseCommand("scan", c.args)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{}
		det, _, err := loadDetector(flags, cfg)
		if err != nil {
			t.Fatal(err)
		}
		items := make(chan model.Item, 1)
		items <- model.Item{Source: "code", Path: "bundle.js", Text: "const head='AKIA'; const key=head+'NAFGYOEYPXU1DSYP';"}
		close(items)
		fs := prepareScan(flags, scan.Options{Detector: det, Allow: cfg.Allowed}).Collect(t.Context(), items)
		count := 0
		for _, f := range fs {
			if f.Type == "aws_access_key_id" {
				count++
			}
		}
		if count != c.want {
			t.Fatal("CLI reconstruction did not reach immutable scan configuration")
		}
	}
}
