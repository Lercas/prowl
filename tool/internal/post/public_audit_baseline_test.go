package post

import (
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestCredentialBaselineCannotHideChangedPublicPermissions(t *testing.T) {
	key := model.Finding{Type: "gcp_api_key", Path: "app.js", Fingerprint: "same-key"}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := WriteBaseline(path, []model.Finding{key}); err != nil {
		t.Fatal(err)
	}
	baseline, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"read_denied", "public_read_allowed", "search_only", "excess_permissions", "unrestricted", "restrictions_configured", "inconclusive"} {
		for _, inOccurrence := range []bool{false, true} {
			finding := key
			audit := &model.PublicKeyAudit{Status: status}
			if inOccurrence {
				finding.Occurrences = []model.Occurrence{{PublicKeyAudit: audit}}
			} else {
				finding.PublicKeyAudit = audit
			}
			got := baseline.Suppress([]model.Finding{finding})
			if len(got) != 1 {
				t.Fatalf("baseline hid status %s, occurrence=%v", status, inOccurrence)
			}
		}
	}
	if got := baseline.Suppress([]model.Finding{key}); len(got) != 0 {
		t.Fatal("ordinary credential suppression changed")
	}
}

func TestPublicAuditBaselineDoesNotAcceptCredentialIdentity(t *testing.T) {
	for _, inOccurrence := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "baseline.json")
		key := model.Finding{Type: "gcp_api_key", Path: "app.js", Fingerprint: "audited-key"}
		audit := &model.PublicKeyAudit{Status: "read_denied"}
		if inOccurrence {
			key.Occurrences = []model.Occurrence{{PublicKeyAudit: audit}}
		} else {
			key.PublicKeyAudit = audit
		}
		ordinary := model.Finding{Type: "github_pat", Fingerprint: "ordinary-key"}
		if err := WriteBaseline(path, []model.Finding{key, ordinary}); err != nil {
			t.Fatal(err)
		}
		baseline, err := LoadBaseline(path)
		if err != nil {
			t.Fatal(err)
		}
		key.PublicKeyAudit, key.Occurrences = nil, nil
		got := baseline.Suppress([]model.Finding{key, ordinary})
		if len(got) != 1 || got[0].Fingerprint != key.Fingerprint {
			t.Fatalf("audit accepted credential identity, occurrence=%v: %+v", inOccurrence, got)
		}
	}
}
