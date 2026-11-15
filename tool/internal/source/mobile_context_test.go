package source

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestMobileRawMemberDigestAndAcquisitionBoundary(t *testing.T) {
	body := []byte{0xff, 0xfe, 'P', 0, 'W', 0, '=', 0, 'x', 0}
	p := makeAPK(t, map[string][]byte{"res/secret #?秘密.env": body})
	ctx := model.WithProvenance(t.Context(), map[string]any{"commit": strings.Repeat("f", 40), "digest": strings.Repeat("a", 64), "source_url": "https://foreign.invalid/input"})
	ctx = model.WithSourceLocator(ctx, func(string) string { return "foreign" })
	ch, err := Extract(ctx, p, defaultOpts())
	if err != nil {
		t.Fatal(err)
	}
	items := archiveItems(ch)
	if len(items) != 1 || items[0].Error != nil {
		t.Fatal("mobile fixture not read")
	}
	it := items[0]
	if it.Path != "app.apk!/res/secret #?秘密.env" || it.Text != "PW=x" || it.MobileEntry != 1 {
		t.Fatal("display or decoded content changed")
	}
	u, err := url.Parse(it.ArtifactURI)
	if err != nil || u.Scheme != "mobile+file" || u.Path != filepath.ToSlash(p) || u.Fragment != "/res/secret #?秘密.env" {
		t.Fatal("member URI confused archive/member components")
	}
	sum := sha256.Sum256(body)
	if it.Meta["digest"] != hex.EncodeToString(sum[:]) || it.Meta["source_transform"] != "mobile-text-decoded" || it.Meta["source_url"] != it.ArtifactURI || it.Meta["commit"] != nil {
		t.Fatal("mobile member inherited foreign provenance or hashed decoded text")
	}
}

func TestMobileSameBasenameUsesDistinctArchiveNamespace(t *testing.T) {
	var items []model.Item
	for i := 0; i < 2; i++ {
		p := makeAPK(t, map[string][]byte{"assets/prod.env": []byte("PW=owned")})
		ch, err := Extract(t.Context(), p, defaultOpts())
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, archiveItems(ch)...)
	}
	if len(items) != 2 || items[0].Path != items[1].Path || items[0].ArtifactURI == items[1].ArtifactURI || items[0].IdentityPath == items[1].IdentityPath {
		t.Fatal("same basename collapsed mobile acquisition")
	}
	if items[0].Meta["digest"] != items[1].Meta["digest"] {
		t.Fatal("equal raw member bytes changed digest")
	}
}

func TestMobileOriginSurvivesTemporaryDownloadPaths(t *testing.T) {
	var items []model.Item
	var policies []string
	for _, origin := range []string{"https://alice:PRIVATE_A@example.invalid/app.apk?signature=PRIVATE_ONE", "https://alice:PRIVATE_A@example.invalid/app.apk?signature=PRIVATE_ONE", "https://bob:PRIVATE_B@example.invalid/app.apk?signature=PRIVATE_TWO"} {
		p := makeAPK(t, map[string][]byte{"assets/prod.env": []byte("PW=owned")})
		coverage := model.NewCoverage()
		coverage.SetIdentityScope(bytes.Repeat([]byte{7}, 32))
		ctx := model.WithCoverage(t.Context(), coverage)
		opts := defaultOpts()
		opts.Origin = origin
		ch, err := Extract(ctx, p, opts)
		if err != nil {
			t.Fatal(err)
		}
		batch := archiveItems(ch)
		if len(batch) != 1 {
			t.Fatal("mobile archive not emitted")
		}
		items = append(items, batch[0])
		scopes := model.NewResult(nil, coverage).Scope
		// Scope target/diagnostics are public; the selection is retained only in its keyed policy hash.
		raw, _ := json.Marshal(scopes)
		if strings.Contains(string(raw), "PRIVATE_") {
			t.Fatal("scope exposed URL credential/query")
		}
		for _, s := range scopes {
			if s.Kind == "mobile" {
				policies = append(policies, s.Policy)
			}
		}
	}
	if len(policies) != 3 || policies[0] != policies[1] || policies[0] == policies[2] {
		t.Fatal("download policy depends on spool path or mixes request selectors")
	}
	if items[0].ArtifactURI != items[1].ArtifactURI || items[0].IdentityPath != items[1].IdentityPath || items[0].IdentityPath == items[2].IdentityPath {
		t.Fatal("private acquisition identity lost selected URL")
	}
	for _, it := range items {
		raw, _ := json.Marshal(it)
		if strings.Contains(string(raw), "PRIVATE_") {
			t.Fatal("private URL serialized in source item")
		}
	}
}

func TestMobileBorrowedBytesAndDuplicateEntries(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for i := 0; i < 2; i++ {
		entry, err := w.Create("res/values.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = entry.Write([]byte("PW=owned")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	name := "https://alice:PRIVATE@example.invalid/app.apk?signature=PRIVATE_QUERY"
	ch, err := MobileBytes(t.Context(), name, b.Bytes(), defaultOpts())
	if err != nil {
		t.Fatal(err)
	}
	items := archiveItems(ch)
	if len(items) != 2 || items[0].Path != items[1].Path || items[0].ArtifactURI != items[1].ArtifactURI || items[0].MobileEntry != 1 || items[1].MobileEntry != 2 {
		t.Fatal("duplicate ZIP entry observations were lost")
	}
	for _, it := range items {
		u, err := url.Parse(it.ArtifactURI)
		if err != nil || u.Scheme != "mobile+payload" {
			t.Fatal("borrowed bytes claimed a remote acquisition")
		}
		raw, _ := json.Marshal(it)
		if strings.Contains(string(raw), "PRIVATE") {
			t.Fatal("borrowed locator exposed private URL data")
		}
	}
}

func TestMobileBinaryDigestAndFailureDoNotInventText(t *testing.T) {
	body := append([]byte{0, 1, 2}, []byte("OWNED_BINARY_TEXT\x00")...)
	p := makeAPK(t, map[string][]byte{"classes.dex": body})
	ch, err := Extract(t.Context(), p, defaultOpts())
	if err != nil {
		t.Fatal(err)
	}
	items := archiveItems(ch)
	sum := sha256.Sum256(body)
	if len(items) != 1 || items[0].Meta["source_transform"] != "mobile-printable-strings" || items[0].Meta["digest"] != hex.EncodeToString(sum[:]) {
		t.Fatal("binary provenance describes a generated text checksum")
	}
	coverage := model.NewCoverage()
	ctx := model.WithCoverage(t.Context(), coverage)
	opts := defaultOpts()
	opts.Origin = "https://u:PRIVATE@example.invalid/app.apk?x=PRIVATE_QUERY"
	failed := archiveItems(MobileFailure(ctx, "app.apk", opts))
	complete, _, _ := coverage.Snapshot()
	if complete || len(failed) != 1 || failed[0].Error == nil || failed[0].Meta["digest"] != nil || failed[0].ArtifactURI == "" {
		t.Fatal("failed acquisition invented content or certified completion")
	}
	raw, _ := json.Marshal(failed)
	if strings.Contains(string(raw), "PRIVATE") {
		t.Fatal("failed acquisition leaked its URL")
	}
}

func TestMobileInvalidOriginDoesNotReadSelectedFile(t *testing.T) {
	opts := defaultOpts()
	opts.Origin = "file:///outside/PRIVATE"
	_, err := Extract(t.Context(), filepath.Join(t.TempDir(), "missing.apk"), opts)
	if err == nil || !strings.Contains(err.Error(), "acquisition URL") {
		t.Fatal("origin override did not fail before opening the source")
	}
}
