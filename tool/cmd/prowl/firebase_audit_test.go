package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/post"
	"github.com/Lercas/prowl/tool/internal/scan"
)

func TestFirestoreAuditFlagScopeAndValidation(t *testing.T) {
	for _, command := range []string{"domain", "mobile"} {
		for _, args := range [][]string{
			{"--audit-firestore-collection", "public"},
			{"--audit-firestore-collection", "public", "--audit-public"},
			{"--audit-firestore-collection", "users/id", "--audit-public", "--authorized"},
			{"--audit-firestore-collection", "../users", "--audit-public", "--authorized"},
			{"--audit-firestore-collection", "https://attacker.invalid", "--audit-public", "--authorized"},
		} {
			if _, _, err := parseCommand(command, args); err == nil {
				t.Fatal("invalid Firestore audit selection accepted", command, args)
			}
		}
		c, _, err := parseCommand(command, []string{"--audit-public", "--authorized", "--audit-firestore-collection", "public", "--audit-firestore-collection", "teams/owned/items"})
		if err != nil || len(c.auditCollections) != 2 {
			t.Fatal("valid explicit collection selection failed", err)
		}
	}
	for _, command := range []string{"scan", "repo", "bucket", "serve", "mcp", "lsp"} {
		if _, _, err := parseCommand(command, []string{"--audit-firestore-collection", "public"}); err == nil {
			t.Fatal("collection scope escaped domain/mobile")
		}
	}
}

func TestPublicAuditSurvivesCredentialBaselineInReport(t *testing.T) {
	for _, format := range []string{"json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			key := model.Finding{Type: "gcp_api_key", Path: "app.js", Severity: "high", Fingerprint: "same-key"}
			baseline := filepath.Join(dir, "baseline.json")
			if err := post.WriteBaseline(baseline, []model.Finding{key}); err != nil {
				t.Fatal(err)
			}
			for _, status := range []string{"read_denied", "public_read_allowed"} {
				key.PublicKeyAudit = &model.PublicKeyAudit{Provider: "firebase", Status: status}
				output := filepath.Join(dir, status+".json")
				code := reportFindings(commonFlags{format: format, output: output, baseline: baseline, noAutoPolicy: true, silence: true, failOn: "high"}, []model.Finding{key}, time.Second)
				if code != 1 {
					t.Fatalf("audit disappeared from severity gate: status=%s code=%d", status, code)
				}
				raw, err := os.ReadFile(output)
				if err != nil || !strings.Contains(string(raw), status) || !strings.Contains(string(raw), "public_key_audit") {
					t.Fatalf("audit disappeared from %s report: %v", format, err)
				}
			}
		})
	}
}

func TestAuditSetupCannotEraseMLFailureOrConsumeInput(t *testing.T) {
	c := commonFlags{auditPublic: true, auditCollections: []string{"public"}, mlEmbed: true, mlModel: filepath.Join(t.TempDir(), "missing-model.json")}
	p := prepareScan(c, scan.Options{})
	if p.mlError == nil || p.auditError != nil {
		t.Fatal("audit setup erased independent ML error")
	}
	c = commonFlags{auditPublic: true, auditCollections: []string{"users/id"}}
	p = prepareScan(c, scan.Options{})
	if p.auditError == nil {
		t.Fatal("invalid internal audit selection failed open")
	}
	items := make(chan model.Item, 1)
	items <- model.Item{Source: "code", Path: "owned.json", Text: "owned fixture"}
	close(items)
	fs := p.Collect(context.Background(), items)
	if len(items) != 1 || len(fs) != 1 || !model.IsIncompleteFinding(fs[0]) {
		t.Fatal("invalid audit configuration read input or claimed success")
	}
}

func TestPartialFirebaseAccessSurvivesDeduplication(t *testing.T) {
	chosen := model.Finding{PublicKeyAudit: &model.PublicKeyAudit{Provider: "firebase", Status: "read_denied"}}
	partial := model.Finding{PublicKeyAudit: &model.PublicKeyAudit{Provider: "firebase", Status: "inconclusive", Checks: []model.PublicAuditCheck{{Service: "rtdb", Status: "public_read_allowed"}, {Service: "storage", Status: "inconclusive"}}}}
	combineFindingSummary(&chosen, partial)
	if !chosen.PublicKeyAudit.HasAccessObservation() || chosen.PublicKeyAudit.Status != "inconclusive" || chosen.Verified != nil {
		t.Fatal("partial observed access lost during aggregation")
	}
}
