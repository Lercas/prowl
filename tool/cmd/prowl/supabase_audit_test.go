package main

import (
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/scan"
)

func TestSupabaseAuditTableFlagScope(t *testing.T) {
	for _, command := range []string{"domain", "mobile"} {
		for _, args := range [][]string{
			{"--audit-supabase-table", "owned_table"},
			{"--audit-supabase-table", "owned_table", "--audit-public"},
			{"--audit-supabase-table", "public.table", "--audit-public", "--authorized"},
			{"--audit-supabase-table", "rpc/mutate", "--audit-public", "--authorized"},
			{"--audit-supabase-table", "owned", "--audit-public", "--authorized", "--verify"},
		} {
			if _, _, err := parseCommand(command, args); err == nil {
				t.Fatal("invalid table audit flags accepted", command, args)
			}
		}
		c, _, err := parseCommand(command, []string{"--audit-public", "--authorized", "--audit-supabase-table", "b", "--audit-supabase-table", "a", "--audit-supabase-table", "b"})
		if err != nil || strings.Join(c.auditTables, ",") != "a,b" {
			t.Fatal("explicit table canonicalization failed", err)
		}
	}
	for _, command := range []string{"scan", "repo", "bucket", "cicd", "org", "serve", "mcp", "lsp"} {
		if _, _, err := parseCommand(command, []string{"--audit-supabase-table", "owned"}); err == nil {
			t.Fatal("table flag escaped audit command scope", command)
		}
	}
}

func TestSupabaseAuditSetupErrorIsSeparateFromML(t *testing.T) {
	p := prepareScan(commonFlags{auditPublic: true, auditTables: []string{"rpc/mutate"}}, scan.Options{})
	if p.auditError == nil || p.mlError != nil {
		t.Fatal("invalid target not recorded as independent audit setup failure")
	}
}
