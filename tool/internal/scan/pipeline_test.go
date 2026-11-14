package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
)

func TestPipelinePrivacyIsolatedAcrossOverlappingScans(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	const custom = "CUSTOM_Zx7Q9Rt5Uv3W8Np2"
	det := detector(t)
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "owned.yaml"), []byte(`id: owned-token
info:
  name: owned token
  severity: high
matchers:
  - type: regex
    regex: ['CUSTOM_[A-Za-z0-9]+']
`), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	item := model.Item{Text: `AWS="` + key + `"` + "\n" + custom, Source: "code", Path: "prod.env"}
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "single item", true: "worker pool"}[stream], func(t *testing.T) {
			arrived := make(chan struct{}, 2)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			makePipeline := func(reveal bool) *Pipeline {
				var first sync.Once
				return New(Options{Detector: det, Rules: engine, Workers: 2, RevealSecrets: reveal, Allow: func(string, string) bool {
					first.Do(func() { arrived <- struct{}{}; <-release })
					return false
				}})
			}
			type result struct {
				reveal   bool
				findings []model.Finding
			}
			results := make(chan result, 2)
			for _, reveal := range []bool{false, true} {
				p := makePipeline(reveal)
				go func() {
					var findings []model.Finding
					if stream {
						findings = p.Run(context.Background(), feed(item))
					} else {
						findings = p.Findings(context.Background(), item)
					}
					results <- result{reveal, findings}
				}()
			}
			for range 2 {
				select {
				case <-arrived:
				case <-time.After(5 * time.Second):
					t.Fatal("scans did not overlap before redaction")
				}
			}
			unblock()
			for range 2 {
				var got result
				select {
				case got = <-results:
				case <-time.After(5 * time.Second):
					t.Fatal("overlapping scan did not finish")
				}
				if len(got.findings) != 2 {
					t.Fatalf("lost builtin/rule coverage: %+v", got.findings)
				}
				for _, finding := range got.findings {
					want := map[string]string{"aws_access_key_id": key, "owned-token": custom}[finding.Type]
					if want == "" {
						t.Fatalf("unexpected fixture finding: %+v", finding)
					}
					if got.reveal && (finding.Redacted != want || finding.Context == nil) {
						t.Fatal("explicit disclosure was changed by another scan")
					}
					if !got.reveal && (finding.Redacted == want || finding.Context != nil) {
						t.Fatal("masked scan disclosed a value or source context")
					}
				}
				raw, err := json.Marshal(got.findings)
				if err != nil {
					t.Fatal(err)
				}
				if !got.reveal && (strings.Contains(string(raw), key) || strings.Contains(string(raw), custom)) {
					t.Fatal("masked serialized response contains a raw value")
				}
			}
		})
	}
}

func TestPipelineSnapshotsOptionsAndPreservesExistingPolicy(t *testing.T) {
	const key = "AKIANAFGYOEYPXU1DSYP"
	item := model.Item{Text: `AWS="` + key + `"`, Source: "code", Path: "prod.env"}
	options := Options{Detector: detector(t)}
	masked := New(options)
	options.RevealSecrets = true
	options.Detector = nil
	revealed := masked.WithRevealSecrets(true)
	maskedAgain := revealed.WithRevealSecrets(false)
	for _, p := range []*Pipeline{masked, maskedAgain} {
		findings := p.Findings(context.Background(), item)
		if len(findings) != 1 || findings[0].Redacted == key || findings[0].Context != nil {
			t.Fatal("an options update changed an existing pipeline")
		}
	}
	if findings := revealed.Findings(context.Background(), item); len(findings) != 1 || findings[0].Redacted != key {
		t.Fatal("derived pipeline changed its original")
	}
}
