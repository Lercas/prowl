package verify

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	bundledverifiers "github.com/Lercas/prowl/tool/verifiers"
	"testing"
	"testing/fstest"
	"time"
)

func ownedEmbeddedVerifier(body string) fstest.MapFS {
	digest := sha256.Sum256([]byte(body))
	return fstest.MapFS{"owned.yaml": {Data: []byte(body)}, "MANIFEST.sha256": {Data: []byte(fmt.Sprintf("%x  owned.yaml\n", digest))}}
}

func TestEmbeddedVerifierSnapshotParity(t *testing.T) {
	emb, err := LoadEmbedded(time.Second, bundledverifiers.Files)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := Load(time.Second, "../../verifiers")
	if err != nil {
		t.Fatal(err)
	}
	if emb.Count() != disk.Count() || emb.Count() == 0 {
		t.Fatal("embedded verifier inventory differs")
	}
	a, err := json.Marshal(emb.verifiers)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(disk.verifiers)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("embedded verifier definitions differ from disk")
	}
}

func TestEmbeddedVerifierStreamAndIntegrity(t *testing.T) {
	const body = "id: owned\nmatch: [owned-type]\nrequests:\n - url: https://owned.invalid/identity\n   matchers:\n    - type: status\n      status: [200]\n"
	for _, mode := range []string{"valid", "duplicate", "unknown", "incomplete", "tampered", "unlisted"} {
		t.Run(mode, func(t *testing.T) {
			text := body
			switch mode {
			case "valid":
				text += "---\n# empty\n---\nid: second\nmatch: [second]\nrequests:\n - url: https://owned.invalid/identity\n"
			case "duplicate":
				text += "---\n" + body
			case "unknown":
				text += "typo: true\n"
			case "incomplete":
				text += "---\ninfo: {name: Broken}\n"
			}
			files := ownedEmbeddedVerifier(text)
			if mode == "tampered" {
				files["owned.yaml"].Data = []byte(body + "# modified\n")
			}
			if mode == "unlisted" {
				files["extra.yaml"] = &fstest.MapFile{Data: []byte(body)}
			}
			set, err := LoadEmbedded(time.Second, files)
			if mode == "valid" {
				if err != nil || set.Count() != 2 {
					t.Fatalf("valid stream: %v", err)
				}
				return
			}
			if err == nil || set != nil {
				t.Fatal("invalid embedded set accepted")
			}
		})
	}
}
