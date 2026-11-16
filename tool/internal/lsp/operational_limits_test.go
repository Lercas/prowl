package lsp

import (
	"github.com/Lercas/prowl/tool/internal/verify"
	"os"
	"testing"
	"time"
)

func TestWorkspaceDoesNotMutateVerifierOperationalDefaults(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PROWL_HOME", t.TempDir())
	defer verify.SetConcurrency(verify.DefaultConcurrency)
	verify.SetConcurrency(7)
	if err := os.WriteFile(".prowl.yaml", []byte("limits: {org_max_pages: 1, clone_timeout: 1ns}\nperformance: {verify_concurrency: 1}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildWithBundled(true); err != nil {
		t.Fatal(err)
	}
	if verify.New(time.Second).Concurrency() != 7 {
		t.Fatal("building editor workspace changed another caller's verifier limit")
	}
}
