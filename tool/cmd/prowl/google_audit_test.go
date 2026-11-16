package main

import (
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/scan"
)

func TestGoogleAuditFlagScopeAndCredentialSetup(t *testing.T) {
	for _, command := range []string{"domain", "mobile"} {
		if _, _, err := parseCommand(command, []string{"--audit-google-restrictions"}); err == nil {
			t.Fatal("missing audit opt-in accepted")
		}
		if _, _, err := parseCommand(command, []string{"--audit-google-restrictions", "--audit-public"}); err == nil {
			t.Fatal("missing authorization accepted")
		}
		for _, verify := range []string{"--verify", "--verify-all", "--verified-only", "--fail-on-verified"} {
			if _, _, err := parseCommand(command, []string{"--audit-google-restrictions", "--audit-public", "--authorized", verify}); err == nil {
				t.Fatal("verification mixed with read-only audit")
			}
		}
		flags, _, err := parseCommand(command, []string{"--audit-google-restrictions", "--audit-public", "--authorized"})
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("PROWL_GOOGLE_AUDIT_TOKEN", "")
		p := prepareScan(flags, scan.Options{})
		if p.auditError == nil || !strings.Contains(p.auditError.Error(), "PROWL_GOOGLE_AUDIT_TOKEN") {
			t.Fatal("missing operator OAuth credential accepted")
		}
		t.Setenv("PROWL_GOOGLE_AUDIT_TOKEN", "owned-operator-token")
		p = prepareScan(flags, scan.Options{})
		if p.auditError != nil {
			t.Fatal(p.auditError)
		}
	}
	for _, command := range []string{"scan", "repo", "org", "mcp", "serve", "image", "bucket", "cicd"} {
		if _, _, err := parseCommand(command, []string{"--audit-google-restrictions"}); err == nil {
			t.Fatal("unsupported source accepted Google metadata audit")
		}
	}
}
