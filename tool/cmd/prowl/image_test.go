package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func localImageFixture(t *testing.T, oversized bool) string {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	files := map[string]string{"prod.env": `AWS = "AKIANAFGYOEYPXU1DSYP"`}
	if oversized {
		files["large.txt"] = strings.Repeat("x", 600)
	}
	for path, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: path, Mode: 0o600, Typeflag: tar.TypeReg, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return localImageFromLayerFixture(t, raw.Bytes())
}

func localImageFromLayerFixture(t *testing.T, raw []byte) string {
	t.Helper()
	layer, err := tarball.LayerFromReader(bytes.NewReader(raw)) //nolint:staticcheck // Keep the fixture compatible with the existing reader API.
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	ref, err := name.NewTag("local-test:latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := tarball.WriteToFile(path, ref, img); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestImageDedupeRetainsTheSurvivingRepeatedEntry(t *testing.T) {
	t.Setenv("PROWL_HOME", t.TempDir())
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for i := 0; i < 10; i++ {
		content := strings.Repeat("\n", i) + `AWS = "AKIANAFGYOEYPXU1DSYP"`
		if err := tw.WriteHeader(&tar.Header{Name: "prod.env", Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	img := localImageFromLayerFixture(t, raw.Bytes())
	for _, dedupe := range []bool{true, false} {
		out := filepath.Join(t.TempDir(), "report.json")
		args := []string{img, "--image-input", "tar", "--format", "json", "--output", out, "--silence"}
		if dedupe {
			args = append(args, "--max-per-file", "1")
		} else {
			args = append(args, "--no-dedupe")
		}
		if code := cmdImage(args); code != 0 {
			t.Fatalf("dedupe=%v: exit=%d", dedupe, code)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var report struct{ Findings []model.Finding }
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		count, surviving := 0, 0
		for _, f := range report.Findings {
			if f.Type != "aws_access_key_id" {
				continue
			}
			count++
			if f.InFinalImage == nil {
				t.Fatal("complete repeated-entry scan lost final-image attribution")
			}
			if *f.InFinalImage {
				surviving++
				if f.Line != 10 {
					t.Fatal("dedupe selected an overwritten occurrence")
				}
			}
		}
		want := 10
		if dedupe {
			want = 1
		}
		if count != want || surviving != 1 {
			t.Fatalf("dedupe=%v: count=%d surviving=%d", dedupe, count, surviving)
		}
		if bytes.Contains(data, []byte("ImageEntry")) || bytes.Contains(data, []byte("image_entry")) {
			t.Fatal("internal entry identity leaked into JSON")
		}
	}
}

func TestImagePartialResultPreventsBaseline(t *testing.T) {
	t.Setenv("PROWL_HOME", t.TempDir())
	for _, mode := range []string{"missing", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			img := localImageFixture(t, mode == "oversized")
			for _, baseline := range []bool{false, true} {
				out := filepath.Join(t.TempDir(), "report.json")
				base := filepath.Join(t.TempDir(), "baseline.json")
				args := []string{img}
				if mode == "missing" {
					args = append(args, filepath.Join(t.TempDir(), "missing.tar"))
				}
				args = append(args, "--image-input", "tar", "--max-size", "512", "--fail-on", "high", "--format", "json", "--output", out, "--silence")
				if baseline {
					args = append(args, "--write-baseline", base)
				}
				if code := cmdImage(args); code != 2 {
					t.Errorf("baseline=%v incomplete image scan returned %d", baseline, code)
				}
				if baseline {
					if _, err := os.Stat(base); !os.IsNotExist(err) {
						t.Errorf("baseline created from incomplete image scan: %v", err)
					}
				}
				data, err := os.ReadFile(out)
				if err != nil {
					t.Fatal(err)
				}
				var report struct {
					Truncated bool
					Findings  []model.Finding
				}
				if err := json.Unmarshal(data, &report); err != nil {
					t.Fatal(err)
				}
				failed, found := false, false
				for _, f := range report.Findings {
					failed = failed || model.IsIncompleteFinding(f)
					found = found || f.Type == "aws_access_key_id"
				}
				if !report.Truncated || !failed || !found {
					t.Errorf("partial image report certified complete or lost findings: truncated=%v failed=%v found=%v", report.Truncated, failed, found)
				}
			}
		})
	}
}
