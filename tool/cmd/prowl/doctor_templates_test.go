package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/doctor"
)

func TestDoctorChecksSelectedTemplatesWithoutProviderRequests(t *testing.T) {
	t.Setenv("PROWL_HOME", t.TempDir())
	checks := doctorTemplateChecks(commonFlags{})
	if !doctor.Healthy(checks) || len(checks) != 2 || !strings.Contains(checks[0].Detail, "175") || !strings.Contains(checks[1].Detail, "84") {
		t.Fatalf("doctor did not load release inventories: %+v", checks)
	}
	for _, name := range []string{"rules", "verifiers"} {
		home := t.TempDir()
		t.Setenv("PROWL_HOME", home)
		dir := filepath.Join(home, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("not: [valid"), 0600); err != nil {
			t.Fatal(err)
		}
		if doctor.Healthy(doctorTemplateChecks(commonFlags{})) {
			t.Fatalf("doctor certified corrupt installed %s", name)
		}
		if checks := doctorTemplateChecks(commonFlags{bundled: true}); !doctor.Healthy(checks) || checks[0].Status != doctor.StatusOK || checks[1].Status != doctor.StatusOK {
			t.Fatal("explicit bundled mode used or warned about an unselected installed set")
		}
	}
	t.Setenv("PROWL_HOME", t.TempDir())
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()
	dir := t.TempDir()
	definition := "id: mock\nmatch: [mock]\nrequests:\n  - method: GET\n    url: " + srv.URL + "\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(filepath.Join(dir, "mock.yaml"), []byte(definition), 0600); err != nil {
		t.Fatal(err)
	}
	if !doctor.Healthy(doctorTemplateChecks(commonFlags{verifiers: []string{dir}})) || calls.Load() != 0 {
		t.Fatal("doctor exercised a provider or could not validate a selected verifier")
	}
	writeTemplate(t, installedRulesDir(), "older-installed-rule")
	checks = doctorTemplateChecks(commonFlags{})
	if !doctor.Healthy(checks) || checks[0].Status != doctor.StatusWarn || !strings.Contains(checks[0].Detail, "overrides bundled") {
		t.Fatal("installed overlay was hidden or treated as a load failure")
	}
}

func TestBundledTemplateSelectionIsExplicitAndMCPCompatible(t *testing.T) {
	for _, c := range []commonFlags{{bundled: true, rulesOnly: true}, {bundled: true, rulesDir: []string{"custom"}}, {bundled: true, verifiers: []string{"custom"}}} {
		if validateTemplateSelection(c) == nil {
			t.Fatal("conflicting template selection silently ignored an explicit source")
		}
	}
	if !knownFlags["--bundled"] || validateTemplateSelection(commonFlags{bundled: true}) != nil {
		t.Fatal("bundled mode is not a valid CLI option")
	}
	if cmdMCP([]string{"--bundled"}) != 2 {
		t.Fatal("MCP silently ignored a startup scan flag")
	}
	argv, err := mcpArgv("prowl_scan", map[string]any{"path": "production.json", "bundled": true})
	if err != nil || !strings.Contains(strings.Join(argv, " "), "--bundled") {
		t.Fatal("MCP did not forward explicit bundled selection")
	}
}
