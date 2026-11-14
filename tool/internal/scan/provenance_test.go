package scan

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/source"
)

func reportMAC(key []byte, text string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(text))
	return hex.EncodeToString(m.Sum(nil))
}

func TestReleasedReportIdentityIsScopedAndPipelineOwnsKey(t *testing.T) {
	const raw = "AKIANAFGYOEYPXU1DSYP"
	key := []byte(strings.Repeat("k", 32))
	p := New(Options{Detector: detector(t), IdentityKey: key})
	key[0] = 'x' // The caller cannot mutate an already prepared scan.
	owned := []byte(strings.Repeat("k", 32))
	a := p.Findings(t.Context(), model.Item{Text: raw, Source: "code", Path: "a.go"})[0]
	b := p.Findings(t.Context(), model.Item{Text: raw, Source: "jira", Path: "SEC-42"})[0]
	if a.SecretID != reportMAC(owned, raw) || a.SecretID != b.SecretID || a.OccurrenceID == b.OccurrenceID || a.OccurrenceID == "" {
		t.Fatal("value identity is not scoped separately from its occurrences")
	}
	if a.Fingerprint != reportMAC(owned, "fingerprint\x00aws_access_key_id\x00a.go\x00"+raw) {
		t.Fatal("released keyed fingerprint contract changed")
	}
	other := New(Options{Detector: detector(t), IdentityKey: key}).Findings(t.Context(), model.Item{Text: raw, Path: "a.go"})[0]
	if a.SecretID == other.SecretID || a.IdentityScope == other.IdentityScope {
		t.Fatal("organization identities share a scope")
	}
	plain := New(Options{Detector: detector(t)}).Findings(t.Context(), model.Item{Text: raw, Path: "a.go"})[0]
	if plain.SecretID != "" || plain.OccurrenceID != "" || plain.Fingerprint != model.ComputeFingerprint(plain.Type, "a.go", raw) {
		t.Fatal("keyless baseline identity changed")
	}
}

func TestReleasedOccurrenceUsesMappedEvidence(t *testing.T) {
	const raw = "AKIANAFGYOEYPXU1DSYP"
	p := New(Options{Detector: detector(t), IdentityKey: []byte(strings.Repeat("k", 32)), Reconstruct: true})
	for _, c := range []struct {
		path, text string
		count      int
	}{
		{"production.json", `{"first":"` + escapedJSON(raw) + `","second":"` + escapedJSON(raw) + `"}`, 2},
		{"production.yaml", "definition: &a " + raw + "\none: {key: *a}\ntwo: {key: *a}\n", 3},
		{"bundle.js", "const head='AKIA';\nconst a=head+'NAFGYOEYPXU1DSYP';\nconst b=head+'NAFGYOEYPXU1DSYP';", 2},
	} {
		fs := p.Findings(t.Context(), model.Item{Path: c.path, Source: "code", Text: c.text})
		ids := map[string]bool{}
		for _, f := range fs {
			if f.Type != "aws_access_key_id" {
				continue
			}
			if f.SecretID != reportMAC(p.options.IdentityKey, raw) || f.OccurrenceID == "" || ids[f.OccurrenceID] || len(f.Evidence) == 0 {
				t.Fatal("mapped occurrences lost identity or proof")
			}
			copy := f
			copy.OccurrenceID = ""
			p.annotateOccurrence(&copy)
			if copy.OccurrenceID != f.OccurrenceID {
				t.Fatal("occurrence identity was computed before coordinate/evidence mapping")
			}
			ids[f.OccurrenceID] = true
		}
		if len(ids) != c.count {
			t.Fatal("missing logical or reconstructed occurrence")
		}
	}
}

func TestReleasedProvenanceIsSanitizedBoundedAndDoesNotMutateInput(t *testing.T) {
	const raw = "AKIANAFGYOEYPXU1DSYP"
	meta := map[string]any{"blob": strings.Repeat("b", 40), "digest": "not-immutable", "run_id": 12, "source_url": "https://user:private-password@example.invalid/file?token=private-query", "ignored": "private-other"}
	ctx := model.WithProvenance(t.Context(), map[string]any{"commit": strings.Repeat("c", 40), "run_id": 13})
	item := model.Item{Text: raw, Path: "https://user:private-password@example.invalid/file?token=private-query", Meta: meta}
	model.AttachProvenance(ctx, &item)
	fs := New(Options{Detector: detector(t)}).Findings(ctx, item)
	if len(fs) != 1 || fs[0].Provenance["blob"] != meta["blob"] || fs[0].Provenance["commit"] != strings.Repeat("c", 40) || fs[0].Provenance["run_id"] != "13" || fs[0].Provenance["digest"] != "" || fs[0].Provenance["ignored"] != "" || meta["run_id"] != 12 {
		t.Fatal("provenance is missing, unvalidated, or mutated its caller")
	}
	encoded, _ := json.Marshal(fs)
	for _, hidden := range []string{"private-password", "private-query", "private-other"} {
		if strings.Contains(string(encoded), hidden) {
			t.Fatal("provenance exposed credentials or unsupported metadata")
		}
	}
	coverage := model.NewCoverage()
	ctx = model.WithCoverage(t.Context(), coverage)
	fs = New(Options{Detector: detector(t)}).Findings(ctx, model.Item{Text: raw, Path: "prod.env", Meta: map[string]any{"source_map": strings.Repeat("x", 2049)}})
	complete, _, diagnostics := coverage.Snapshot()
	if complete || len(diagnostics) != 1 || diagnostics[0].Code != "provenance_limit" || len(fs) != 2 || !model.IsIncompleteFinding(fs[1]) {
		t.Fatal("oversized provenance looks like complete coverage")
	}
}

func TestReleasedSourceProvenanceSurvivesProducerContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prod.env")
	if err := os.WriteFile(path, []byte("AWS=AKIANAFGYOEYPXU1DSYP"), 0600); err != nil {
		t.Fatal(err)
	}
	parent := model.WithProvenance(t.Context(), map[string]any{"run_id": 12})
	producer := model.WithProvenance(parent, map[string]any{"run_id": 13, "artifact_id": "owned-artifact"})
	fs := New(Options{Detector: detector(t)}).Run(parent, source.Filesystem(producer, []string{path}, nil, 1000))
	if len(fs) != 1 || fs[0].Provenance["run_id"] != "13" || fs[0].Provenance["artifact_id"] != "owned-artifact" {
		t.Fatal("consumer context overwrote or lost the producer's source evidence")
	}
}

func TestReleasedKeyedIdentityKeepsSuppressedGitObservations(t *testing.T) {
	g, fs := timelineFixture()
	g.Commits = g.Commits[:2]
	g.Head = "c2"
	p := New(Options{Detector: detector(t), IdentityKey: []byte(strings.Repeat("k", 32)), ML: fixedMLScorer{results: []mlscore.Result{{Score: 0}}, threshold: .3}})
	it := model.Item{Source: "code", Path: "prod.env", Text: "AWS=AKIANAFGYOEYPXU1DSYP", Meta: map[string]any{"git_history": fs[1].GitRecord}}
	if out := p.Findings(t.Context(), it); len(out) != 0 {
		t.Fatal("ML fixture was not suppressed")
	}
	fs = fs[:1]
	fs[0].Fingerprint = p.reportFingerprint("aws_access_key_id", "prod.env", "AKIANAFGYOEYPXU1DSYP")
	fs = FinalizeGitTimeline(fs)
	if fs[0].Git.InHEAD == nil || !*fs[0].Git.InHEAD || len(fs[0].Git.Removals) != 0 {
		t.Fatal("keyed report identity turned ML suppression into a Git removal")
	}
}
