package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
)

func TestConfiguredPipelineFreezesImportedAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned.toml")
	text := "[[rules]]\nid='owned-import-rule'\nregex='IMPORTED_[A-Z0-9]{8}'\n[allowlist]\nstopwords=['AABBCCDD']\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	flags := commonFlags{rules: []string{path}, noAutoPolicy: true}
	cfg := &config.Config{}
	det, _, err := loadDetector(flags, cfg)
	if err != nil {
		t.Fatal(err)
	}
	pipeline := scan.New(scan.Options{Detector: det, Config: cfg})
	cfg.MergeAllowlist(nil, nil, []string{"Q7K8M9N0"})
	coverage := model.NewCoverage()
	fs := pipeline.Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: "prod.env", Text: "IMPORTED_AABBCCDD\nIMPORTED_Q7K8M9N0"})
	found := 0
	for _, f := range fs {
		if f.Type == "owned_import_rule" {
			found++
		}
	}
	report := model.NewResult(fs, coverage)
	if found != 1 || !report.Complete || !report.Filtered {
		t.Fatal("final merged policy did not freeze", fs, report)
	}
	data, _ := json.Marshal(report.Scope)
	if strings.Contains(string(data), "AABBCCDD") || strings.Contains(string(data), path) {
		t.Fatal("configuration identity leaked imported policy")
	}
	foundScope := false
	for _, s := range report.Scope {
		if s.Kind == "detector_config" {
			foundScope = true
		}
	}
	if !foundScope {
		t.Fatal("final config scope omitted")
	}
}
