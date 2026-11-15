package main

import (
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
	"testing"
)

func TestPublicAuditAuthorizationAndScope(t *testing.T) {
	for _, command := range []string{"domain", "mobile"} {
		for _, args := range [][]string{
			{"--audit-public"}, {"--audit-public", "--authorized=false"},
			{"--audit-public", "--authorized", "--verify"}, {"--audit-public", "--authorized", "--verify-all"},
			{"--audit-public", "--authorized", "--verified-only"}, {"--audit-public", "--authorized", "--fail-on-verified"},
		} {
			if _, _, err := parseCommand(command, args); err == nil {
				t.Fatal("missing authorization or write-capable combination accepted", command, args)
			}
		}
		c, _, err := parseCommand(command, []string{"--audit-public", "--authorized"})
		if err != nil || !c.auditPublic || c.verify {
			t.Fatal("audit enabled ordinary verifier", err)
		}
		prepared := prepareScan(c, scan.Options{})
		_, stages := prepared.pipeline.Capabilities()
		if !stages["public_key_audit"] || stages["verification"] {
			t.Fatal("incorrect audit stages", stages)
		}
		if _, _, err := parseCommand(command, []string{"--audit-public=false"}); err != nil {
			t.Fatal("explicit opt out requires authorization", err)
		}
	}
	for _, command := range []string{"scan", "repo", "image", "bucket", "cicd", "serve", "mcp", "lsp", "compare"} {
		if _, _, err := parseCommand(command, []string{"--audit-public", "--authorized"}); err == nil {
			t.Fatal("audit escaped domain/mobile scope", command)
		}
	}
}

func TestPublicAuditSummaryDoesNotChangeLiveness(t *testing.T) {
	chosen := model.Finding{Type: "algolia-api-key", PublicKeyAudit: &model.PublicKeyAudit{Provider: "algolia", Status: "search_only"}}
	other := model.Finding{PublicKeyAudit: &model.PublicKeyAudit{Provider: "algolia", Status: "excess_permissions"}}
	combineFindingSummary(&chosen, other)
	if chosen.PublicKeyAudit.Status != "excess_permissions" || chosen.Verified != nil || chosen.Verification != nil {
		t.Fatal("audit lost risk or changed liveness")
	}
	if chosen.Occurrence().PublicKeyAudit != chosen.PublicKeyAudit {
		t.Fatal("audit missing from occurrence")
	}
}
