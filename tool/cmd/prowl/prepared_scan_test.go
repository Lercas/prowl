package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
)

func TestLoadingAnotherCLIConfigurationCannotChangePreparedDisclosure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.yaml")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	maskedFlags := commonFlags{config: path, workers: 1}
	cfg := &config.Config{}
	det, _, err := loadDetector(maskedFlags, cfg)
	if err != nil {
		t.Fatal(err)
	}
	masked := prepareScan(maskedFlags, scan.Options{Detector: det, Allow: cfg.Allowed})
	revealedFlags := maskedFlags
	revealedFlags.showSecrets = true
	if _, err := loadConfig(&revealedFlags); err != nil {
		t.Fatal(err)
	}
	revealed := prepareScan(revealedFlags, scan.Options{Detector: det, Allow: cfg.Allowed})
	if _, err := loadConfig(&maskedFlags); err != nil {
		t.Fatal(err)
	}
	const key = "AKIANAFGYOEYPXU1DSYP"
	for _, plan := range []preparedScan{masked, revealed, masked} {
		items := make(chan model.Item, 1)
		items <- model.Item{Text: `AWS="` + key + `"`, Source: "code", Path: "prod.env"}
		close(items)
		findings := plan.Collect(context.Background(), items)
		if len(findings) != 1 {
			t.Fatalf("unexpected findings: %+v", findings)
		}
		if plan.flags.showSecrets != (findings[0].Redacted == key) || plan.flags.showSecrets != (findings[0].Context != nil) {
			t.Fatal("another invocation changed the prepared privacy policy")
		}
	}
}
