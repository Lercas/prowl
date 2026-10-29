//go:build !cgo

package mlfeatures

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestPinnedCompressorIntegrity(t *testing.T) {
	data, err := os.ReadFile("zlib_length_provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var provenance struct {
		ModuleSHA string `json:"module_sha256"`
	}
	if json.Unmarshal(data, &provenance) != nil {
		t.Fatal("invalid compressor provenance")
	}
	h := sha256.Sum256(zlibModule)
	if hex.EncodeToString(h[:]) != provenance.ModuleSHA {
		t.Fatal("compressor differs from pinned artifact")
	}
}
