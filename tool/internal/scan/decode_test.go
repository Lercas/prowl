package scan

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestDecodedFindingPreservesPrivacyAndSourcePosition(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	blob := hex.EncodeToString([]byte("AWS_ACCESS_KEY_ID=" + key))
	item := model.Item{Text: "before\nblob: " + blob + "\n", Path: "prod.env", Source: "code"}
	p := New(Options{Detector: detector(t)})
	findings := p.Findings(t.Context(), item)
	if len(findings) != 1 || findings[0].Type != "aws_access_key_id" {
		t.Fatal("decoded finding was lost")
	}
	f := findings[0]
	if f.Line != 2 || f.Col != 7 || f.UTF16Col != 7 || f.Context != nil || f.Redacted == key ||
		f.Fingerprint != model.ComputeFingerprint(f.Type, item.Path, key) {
		t.Fatal("decoded finding lost original position, value identity, or privacy")
	}
	raw, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(key)) || bytes.Contains(raw, []byte(blob)) {
		t.Fatal("masked JSON disclosed plaintext or the full encoded credential")
	}
	revealed := p.WithRevealSecrets(true).Findings(t.Context(), item)
	if len(revealed) != 1 || revealed[0].Redacted != key || revealed[0].Context == nil || !strings.Contains(revealed[0].Context.Line, blob) {
		t.Fatal("explicit disclosure did not preserve the decoded value and original context")
	}
}

func TestCompressedScanRetainsFindingsAndIncompleteMarker(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte("AWS_ACCESS_KEY_ID=" + key + "\n" + strings.Repeat(" ", 300<<10))); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	item := model.Item{Text: "blob: " + base64.StdEncoding.EncodeToString(b.Bytes()), Path: "prod.env", Source: "code"}
	findings := New(Options{Detector: detector(t)}).Findings(t.Context(), item)
	var matched, incomplete bool
	for _, f := range findings {
		matched = matched || f.Type == "aws_access_key_id"
		incomplete = incomplete || f.Type == ResultsTruncatedType
	}
	if !matched || !incomplete {
		t.Fatal("compressed scan dropped its readable finding or incomplete marker")
	}
}
