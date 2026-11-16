package mlmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadedModelDigestKeepsExactSnapshot(t *testing.T) {
	raw, err := json.Marshal(validOwnedModel(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if first.Digest() != hex.EncodeToString(sum[:]) {
		t.Fatal("identity does not describe loaded bytes")
	}
	replacement := append(append([]byte(nil), raw...), '\n')
	if err := os.WriteFile(path, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	second, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() == second.Digest() || first.Digest() != hex.EncodeToString(sum[:]) {
		t.Fatal("source replacement changed a loaded model or reused its identity")
	}
	a, err := first.Predict(make([]float64, NumFeatures))
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Predict(make([]float64, NumFeatures))
	if err != nil || a != b {
		t.Fatal("identity-only byte change altered inference")
	}
}

func TestEmbeddedModelDigestMatchesCanonicalBytes(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(embedded)
	if m.Digest() != hex.EncodeToString(sum[:]) {
		t.Fatal("embedded snapshot lost its byte identity")
	}
}
