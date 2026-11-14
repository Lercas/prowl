package main

import (
	"testing"

	"github.com/Lercas/prowl/tool/internal/config"
)

func TestConfiguredDisableAppliesBeforeAllRuleProducers(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PROWL_HOME", t.TempDir())
	cfg := &config.Config{}
	cfg.Detectors.Disable = []string{" AWS_ACCESS-KEY_ID ", "Owned-CUSTOM"}
	cfg.Detectors.Custom = []config.CustomRule{{ID: "owned_custom", Regex: "OWNED_[A-Z]{12}", Category: "generic"}}
	_, tax, err := loadDetector(commonFlags{bundled: true}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range tax.Types {
		if cfg.TypeDisabled(typ.ID) {
			t.Fatalf("disabled taxonomy/custom type survived: %s", typ.ID)
		}
	}
	eng, err := loadConfiguredEngine(commonFlags{bundled: true}, cfg)
	if err != nil || eng == nil {
		t.Fatalf("engine: %v", err)
	}
	for _, template := range eng.Templates() {
		if cfg.TypeDisabled(template.ID) {
			t.Fatalf("disabled template survived: %s", template.ID)
		}
	}
	if eng.Len() == 0 || len(tax.Types) == 0 {
		t.Fatal("disable removed unrelated detectors")
	}
}
