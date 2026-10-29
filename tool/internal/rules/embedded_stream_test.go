package rules

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"testing/fstest"

	bundledrules "github.com/Lercas/prowl/tool/rules"
)

func embeddedStream(text string) fstest.MapFS {
	digest := sha256.Sum256([]byte(text))
	return fstest.MapFS{"rules.yaml": {Data: []byte(text)}, "MANIFEST.sha256": {Data: []byte(fmt.Sprintf("%x  rules.yaml\n", digest))}}
}

func TestEmbeddedMultiDocumentStreamAndDuplicateRejection(t *testing.T) {
	const first = "id: first\ninfo: {name: First, severity: high}\nmatchers:\n  - type: regex\n    regex: ['FIRSTMARKER']\n"
	const second = "id: second\ninfo: {name: Second, severity: high}\nmatchers:\n  - type: regex\n    regex: ['SECONDMARKER']\n"
	eng, err := LoadEmbedded(embeddedStream(first + "---\n# empty\n---\n" + second + "---\n"))
	if err != nil || eng.Len() != 2 {
		t.Fatal("embedded stream did not load both nonempty documents")
	}
	hits := eng.Match("SECONDMARKER")
	if len(hits) != 1 || hits[0].RuleID != "second" {
		t.Fatal("embedded second document is inactive")
	}
	if _, err := LoadEmbedded(embeddedStream(first + "---\n" + first)); err == nil {
		t.Fatal("duplicate ID in a later document accepted")
	}
}

func TestEmbeddedAndFilesystemInventoryParity(t *testing.T) {
	emb, err := LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := Load("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	if emb.Len() != 175 || emb.Len() != disk.Len() {
		t.Fatal("embedded and on-disk template inventories differ")
	}
	ids := map[string]bool{}
	public := 0
	for _, tpl := range emb.Templates() {
		ids[tpl.ID] = true
		if tpl.Sensitive != nil && !*tpl.Sensitive {
			public++
		}
	}
	for _, tpl := range disk.Templates() {
		if !ids[tpl.ID] {
			t.Fatal("on-disk rule missing from binary")
		}
	}
	if public != 3 {
		t.Fatal("public metadata inventory changed")
	}
}

func TestMetadataRulesDoNotProduceCredentialFindings(t *testing.T) {
	emb, err := LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"value=pk_live_\x383ea947bc2567d10a5f390c2eb468d91a765ab47",
		"value=org_Kp9aZ2bYwcX4dWqeV8fUmgThS",
		"PLAID_CLIENT_ID=\x383ea947bc2567d10a5f390c2",
	} {
		if len(emb.Match(text)) != 0 {
			t.Fatal("public metadata reported as a credential")
		}
	}
	controls := map[string]string{
		"stripe-restricted-key":     "\x72k_live_Kp9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7",
		"shopify-custom-app-token":  "\x73hpca_\x383ea947bc2567d10a5f390c2eb468d91",
		"shopify-private-app-token": "\x73hppa_\x383ea947bc2567d10a5f390c2eb468d91",
		"shopify-shared-secret":     "\x73hpss_\x383ea947bc2567d10a5f390c2eb468d91",
		"plaid-client-secret":       "PLAID_SECRET=\x383ea947bc2567d10a5f390c2eb468d91",
	}
	for id, text := range controls {
		found := false
		for _, h := range emb.Match(text) {
			if h.RuleID == id {
				found = true
			}
		}
		if !found {
			t.Fatalf("previously skipped credential rule remains inactive: %s", id)
		}
	}
}
