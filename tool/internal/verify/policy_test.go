package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bundledverifiers "github.com/Lercas/prowl/tool/verifiers"
)

const ownedPolicyYAML = `id: owned-policy
match: [aws_access_key_id]
extract: {account: 'tenant_a'}
sign: awsv4
sign_params: {region: us-east-1, service: sts}
requests:
  - method: GET
    url: https://owned.invalid/check
    headers: {Authorization: 'Bearer {{secret}}', X-Owned: private-header-marker}
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
`

func loadPolicyFixture(t *testing.T, path, text string) *Set {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	set, err := Load(time.Second, path)
	if err != nil {
		t.Fatal(err)
	}
	return set
}
func policyFixtureID(t *testing.T, set *Set) string {
	t.Helper()
	id, err := set.PolicyDigest()
	if err != nil || len(id) != 64 {
		t.Fatal("invalid policy identity", err)
	}
	return id
}
func TestLoadedVerifierPolicySnapshotAndSemanticFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned.yaml")
	original := loadPolicyFixture(t, path, ownedPolicyYAML)
	before := policyFixtureID(t, original)
	copy := loadPolicyFixture(t, filepath.Join(dir, "copy.yaml"), "# presentation comment\n"+ownedPolicyYAML)
	if before != policyFixtureID(t, copy) {
		t.Fatal("filename or YAML presentation changed loaded policy")
	}
	for _, tc := range []struct{ from, to string }{
		{"owned-policy", "other-policy"},
		{"aws_access_key_id", "github_pat"},
		{"tenant_a", "tenant_b"},
		{"region: us-east-1", "region: eu-west-1"},
		{"service: sts", "service: s3"},
		{"sign: awsv4", "sign: ''"},
		{"method: GET", "method: POST"},
		{"owned.invalid/check", "owned.invalid/changed"},
		{"private-header-marker", "different-private-header-marker"},
		{"matchers-condition: and", "matchers-condition: or"},
		{"status: [200]", "status: [201]"},
		{"headers:", "capability: identity-read\n    headers:"},
	} {
		replaced := loadPolicyFixture(t, path, strings.Replace(ownedPolicyYAML, tc.from, tc.to, 1))
		if policyFixtureID(t, replaced) == before {
			t.Fatal("semantic field omitted from identity", tc.from)
		}
		if policyFixtureID(t, original) != before {
			t.Fatal("source replacement mutated loaded definitions")
		}
	}
}
func TestBundledAndDiskVerifierPolicyIdentity(t *testing.T) {
	embedded, err := LoadEmbedded(time.Second, bundledverifiers.Files)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := Load(time.Second, "../../verifiers")
	if err != nil {
		t.Fatal(err)
	}
	if policyFixtureID(t, embedded) != policyFixtureID(t, disk) {
		t.Fatal("identical loaded definitions have different identities")
	}
}

func TestLoadedVerifierPolicyPreservesBinaryBodyBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "binary.yaml")
	base := `id: binary
match: [aws_access_key_id]
requests:
 - method: POST
   url: https://owned.invalid/check
   body: !!binary AAH/
   matchers:
    - type: status
      status: [200]
`
	first := loadPolicyFixture(t, path, base)
	second := loadPolicyFixture(t, path, strings.Replace(base, "AAH/", "AAH+", 1))
	if first.verifiers[0].Requests[0].Body == second.verifiers[0].Requests[0].Body {
		t.Fatal("fixture did not load distinct body bytes")
	}
	if policyFixtureID(t, first) == policyFixtureID(t, second) {
		t.Fatal("binary request body identity was lossy")
	}
}
