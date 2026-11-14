package lsp

import (
	"os"
	"testing"
)

func TestWorkspaceDisableMatchesBuiltinAndTemplateSpellings(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PROWL_HOME", t.TempDir())
	line := "AWS=AKIANAFGYOEYPXU1DSYP\n"
	before, err := buildWithBundled(true)
	if err != nil || len(scanDiagnostics(before, "file:///owned/prod.env", line)) == 0 {
		t.Fatalf("positive control: %v", err)
	}
	if err := os.WriteFile(".prowl.yaml", []byte("detectors:\n  disable: [' AWS-Access_KEY-id ']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := buildWithBundled(true)
	if err != nil {
		t.Fatal(err)
	}
	if got := scanDiagnostics(after, "file:///owned/prod.env", line); len(got) != 0 {
		t.Fatalf("disabled type still produced editor diagnostics: %+v", got)
	}
}
