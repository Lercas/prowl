package scan

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/secretindex"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func TestIndexedPipelineLinksValuesAndSanitizesStoredLocations(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	directory := filepath.Join(t.TempDir(), "index")
	store, err := secretindex.Open(t.Context(), directory, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := store.Identity()
	p := New(Options{Detector: detector(t), ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
	path := "https://operator:OtherPassword@host.invalid/" + url.PathEscape(key) + "?key=" + key + "#" + key
	item := model.Item{Source: "code", Path: path, Text: `AWS="` + key + `"`}
	first := p.Findings(t.Context(), item)
	if len(first) != 1 || first[0].ValueFingerprint != id.Fingerprint(key) || strings.Contains(first[0].IndexPath, key) || strings.Contains(first[0].IndexPath, "OtherPassword") || strings.Contains(first[0].IndexPath, "?") {
		t.Fatal("value identity or index path privacy failed")
	}
	item.Source = "jira"
	item.Path = "APP-31"
	second := p.WithRevealSecrets(true).Findings(t.Context(), item)
	if len(second) != 1 || second[0].ValueFingerprint != first[0].ValueFingerprint || second[0].IndexLocationID == first[0].IndexLocationID || second[0].Redacted != key {
		t.Fatal("cross-source identity or independent disclosure policy failed")
	}
	if _, err := store.Record(t.Context(), "scope", time.Now(), true, append(first, second...)); err != nil {
		t.Fatal(err)
	}
	secrets, err := store.Secrets(t.Context(), "")
	if err != nil || len(secrets) != 1 || secrets[0].LocationCount != 2 {
		t.Fatal("pipeline identities did not reach storage")
	}
	raw, err := json.Marshal(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(key)) || bytes.Contains(raw, []byte("OtherPassword")) {
		t.Fatal("index report disclosed a credential")
	}
	plain := New(Options{Detector: detector(t)}).Findings(t.Context(), item)
	encoded, err := json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 1 || plain[0].ValueFingerprint != "" || plain[0].IndexPath != "" || strings.Contains(string(encoded), "value_fingerprint") {
		t.Fatal("index identity was enabled implicitly")
	}
}

func TestIndexURLDisplayDoesNotCollapseDistinctSourceLocations(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	p := New(Options{Detector: detector(t), ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
	var fs []model.Finding
	for _, path := range []string{"https://host.invalid/page?id=1", "https://host.invalid/page?id=2"} {
		fs = append(fs, p.Findings(t.Context(), model.Item{Source: "code", Path: path, Text: `AWS="` + key + `"`})...)
	}
	if len(fs) != 2 || fs[0].IndexPath != fs[1].IndexPath || fs[0].IndexLocationID == fs[1].IndexLocationID {
		t.Fatal("sanitization collapsed original source identities")
	}
}

func TestIndexRetainsProviderRejectionEvenWhenMLSuppressesDisplay(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	previous := safehttp.AllowPrivate.Load()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer api.Close()
	path := filepath.Join(t.TempDir(), "owned.yaml")
	rule := "id: owned-check\nmatch: [aws_access_key_id]\nrequests:\n  - url: " + api.URL + "\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(path, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	verifiers, err := verify.Load(time.Second, path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := secretindex.Open(t.Context(), filepath.Join(t.TempDir(), "index"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := store.Identity()
	var evidence []model.Finding
	options := Options{Detector: detector(t), Verifiers: verifiers, ML: fixedMLScorer{results: []mlscore.Result{{Score: 0}}, threshold: 0.3}, RevealSecrets: true, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location, ObserveVerification: func(f model.Finding) { evidence = append(evidence, f) }}
	item := model.Item{Source: "code", Path: "prod.env", Text: `AWS="` + key + `"`}
	if findings := New(options).Findings(t.Context(), item); len(findings) != 0 {
		t.Fatal("ML suppression policy changed")
	}
	if len(evidence) != 1 || evidence[0].Verified == nil || *evidence[0].Verified || evidence[0].Redacted != "" || evidence[0].Context != nil || evidence[0].Path != "" {
		t.Fatal("verification observer lost rejection or received raw report fields")
	}
	if _, err := store.Record(t.Context(), "scope", time.Now(), true, evidence); err != nil {
		t.Fatal(err)
	}
	secrets, err := store.Secrets(t.Context(), "")
	if err != nil || len(secrets) != 1 || secrets[0].LastConfirmedState != "dead" {
		t.Fatal("rejected credential was lost from state history")
	}
	options.ObserveVerification = func(f model.Finding) { *f.Verified = true }
	if findings := New(options).Findings(t.Context(), item); len(findings) != 0 {
		t.Fatal("observer mutated the pipeline's provider verdict")
	}
}

func TestIndexPreservesSeparateRuleOccurrencesOnOneLine(t *testing.T) {
	dir := t.TempDir()
	rule := "id: owned\ninfo:\n  name: owned\n  severity: high\nmatchers:\n  - type: regex\n    regex: ['OWNED_[A-Za-z0-9]{24}']\n"
	if err := os.WriteFile(filepath.Join(dir, "owned.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	token := "OWNED_S7mV8pQ9rT2nK5xL3cD6bF4a"
	item := model.Item{Source: "code", Path: "app.txt", Text: "x=" + token + " y=" + token}
	options := Options{Detector: detector(t), Rules: engine, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location}
	findings := New(options).Findings(t.Context(), item)
	if len(findings) != 2 || findings[0].IndexLocationID == findings[1].IndexLocationID {
		t.Fatal("separate rule locations collapsed before indexing")
	}
}

func TestIndexMetadataScrubsOtherDetectedValues(t *testing.T) {
	keys := []string{"AKIANAFGYOEYPXU1DSYP", "AKIAIOSFODNN7EXAMPLE"}
	// Exercise the metadata boundary directly so placeholder policy cannot hide
	// the second candidate before the privacy check.
	p := New(Options{ValueFingerprint: func(string) string { return "identity" }})
	path := "https://host.invalid/" + strings.Join(keys, "/") + "?other=credential"
	fs := []model.Finding{{IndexPath: path, IndexSource: strings.Join(keys, ":"), IndexType: keys[1]}, {IndexPath: path, IndexSource: keys[0]}}
	p.sanitizeIndexMetadata(fs, keys)
	for _, f := range fs {
		for _, key := range keys {
			if strings.Contains(f.IndexPath+f.IndexSource+f.IndexType, key) {
				t.Fatal("another detected value escaped into index metadata")
			}
		}
		if strings.Contains(f.IndexPath, "?") {
			t.Fatal("URL query escaped into metadata")
		}
	}
}
