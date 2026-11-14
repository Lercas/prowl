package cicd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestCICDProvenanceAndPolicySkips(t *testing.T) {
	allowLoopback(t)
	content := "AWS=AKIANAFGYOEYPXU1DSYP\n"
	zipped := zipBytes(t, map[string]string{"config.env": content, "image.bin": "binary\x00data"})
	revision := strings.Repeat("a", 40)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owned/app/actions/runs":
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []map[string]any{{"id": 7, "name": "CI", "head_sha": revision, "html_url": "https://user:private@forge.invalid/run/7?signature=private-query"}}})
		case "/repos/owned/app/actions/runs/7/artifacts":
			_, _ = io.WriteString(w, `{"artifacts":[{"id":9,"name":"bundle","expired":false}]}`)
		case "/repos/owned/app/actions/artifacts/9/zip":
			_, _ = w.Write(zipped)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	coverage := model.NewCoverage()
	ctx := model.WithCoverage(context.Background(), coverage)
	items, done, err := Collect(ctx, "github:owned/app", Options{BaseURL: api.URL, Token: "owned-token", IncludeArtifacts: true})
	if err != nil {
		t.Fatal(err)
	}
	got := drain(items)
	result := <-done
	if result.Failures != 0 || result.Items != 1 || result.Skipped != 1 || len(got) != 1 {
		t.Fatalf("policy skip became a failed acquisition: %+v", result)
	}
	meta := got[0].Meta
	digest := sha256.Sum256([]byte(content))
	if meta["commit"] != revision || meta["run_id"] != "7" || meta["artifact_id"] != "9" || meta["digest"] != hex.EncodeToString(digest[:]) || meta["source_url"] != "https://forge.invalid/run/7" || meta["url"] != "https://forge.invalid/run/7" {
		t.Fatalf("lost immutable or safe source provenance: %+v", meta)
	}
	complete, _, ds := coverage.Snapshot()
	if !complete || len(model.NewResult(nil, coverage).Scope) != 1 {
		t.Fatalf("lost acquisition scope or misclassified binary policy: %v", ds)
	}
}

func TestCICDRejectsAmbiguousOrMissingListings(t *testing.T) {
	allowLoopback(t)
	for _, listing := range []string{`{"workflow_runs":[],"workflow_runs":[]}`, `{"workflow_runs":[]} {}`, `null`, `{}`, `{"workflow_runs":null}`, `{"workflow_runs":[{"id":7,"name":"\ud800"}]}`} {
		t.Run(listing, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, listing) }))
			defer api.Close()
			coverage := model.NewCoverage()
			items, done, err := Collect(model.WithCoverage(context.Background(), coverage), "github:owned/app", Options{BaseURL: api.URL, Token: "owned-token", IncludeLogs: true})
			if err != nil {
				t.Fatal(err)
			}
			got := drain(items)
			result := <-done
			complete, _, _ := coverage.Snapshot()
			if result.Failures == 0 || complete || len(got) != 1 || got[0].Error == nil {
				t.Fatalf("invalid listing certified: %+v %+v", result, got)
			}
		})
	}
}

func TestExpiredArtifactPreservesOtherLogsButFailsCoverage(t *testing.T) {
	allowLoopback(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owned/app/actions/runs":
			_, _ = io.WriteString(w, `{"workflow_runs":[{"id":7}]}`)
		case "/repos/owned/app/actions/runs/7/logs":
			_, _ = io.WriteString(w, "AWS=AKIANAFGYOEYPXU1DSYP")
		case "/repos/owned/app/actions/runs/7/artifacts":
			_, _ = io.WriteString(w, `{"artifacts":[{"id":9,"expired":true}]}`)
		default:
			t.Errorf("expired artifact was downloaded: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	coverage := model.NewCoverage()
	items, done, err := Collect(model.WithCoverage(context.Background(), coverage), "github:owned/app", Options{BaseURL: api.URL, Token: "owned-token", IncludeLogs: true, IncludeArtifacts: true})
	if err != nil {
		t.Fatal(err)
	}
	got := drain(items)
	result := <-done
	complete, _, ds := coverage.Snapshot()
	if result.Items != 1 || result.Failures == 0 || complete || len(got) != 2 || got[0].Error != nil || got[1].Error == nil {
		t.Fatalf("expiry hid available logs or incompleteness: %+v %v", result, ds)
	}
}

type contractTransport func(*http.Request) (*http.Response, error)

func (f contractTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type closeFailure struct{ io.Reader }

func (closeFailure) Close() error { return errors.New("owned close failure") }

func TestCIResponseCloseFailuresAreNotCertified(t *testing.T) {
	c := &collector{opts: Options{MaxDownload: 1024}, api: &http.Client{Transport: contractTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: closeFailure{strings.NewReader(`{"workflow_runs":[]}`)}, Request: r}, nil
	})}}
	var out githubRuns
	if err := c.getJSON(context.Background(), "https://owned.invalid/list", &out); err == nil {
		t.Fatal("listing close failure disappeared")
	}
	raw, err := c.download(context.Background(), "https://owned.invalid/log")
	if err == nil || len(raw) == 0 {
		t.Fatal("download close failure lost error or readable bytes")
	}
}

func TestCISourceScopeCapturesAcquisitionPolicyWithoutToken(t *testing.T) {
	allowLoopback(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"workflow_runs":[]}`) }))
	defer api.Close()
	collect := func(token, branch string, size int64) model.Scope {
		coverage := model.NewCoverage()
		items, done, err := Collect(model.WithCoverage(context.Background(), coverage), "github:owned/app", Options{BaseURL: api.URL, Token: token, Branch: branch, MaxDownload: size, IncludeLogs: true})
		if err != nil {
			t.Fatal(err)
		}
		_ = drain(items)
		<-done
		return model.NewResult(nil, coverage).Scope[0]
	}
	first := collect("one", "main", 1024)
	if first != collect("two", "main", 1024) || first.Policy == collect("one", "other", 1024).Policy || first.Policy == collect("one", "main", 2048).Policy {
		t.Fatal("scope ignored acquisition policy or hashed the bearer token")
	}
}

func TestCIMetadataBoundsAndTypedListingAmplification(t *testing.T) {
	many := []byte(`{"workflow_runs":[` + strings.Repeat(`{},`, 100) + `{}]}`)
	var out githubRuns
	if boundListingRows(many, &out) == nil || len(out.Runs) != 0 {
		t.Fatal("oversized page allocated API structs")
	}
	if runLabel(strings.Repeat("name", 1000), 7) != "run-7" || safeItemURL("https://owned.invalid/"+strings.Repeat("x", 3000)) != "" {
		t.Fatal("unbounded metadata reached item locators")
	}
	ch := make(chan model.Item, 1)
	c := &collector{opts: Options{MaxItem: 1024}}
	ctx := model.WithProvenance(context.Background(), map[string]any{"digest": strings.Repeat("f", 64), "commit": strings.Repeat("a", 40)})
	ctx = runContext(ctx, 7, strings.Repeat("private-invalid-revision", 1000))
	var result Result
	if err := c.emitFile(ctx, ch, "ci/log", "", []byte("public=42"), &result); err != nil {
		t.Fatal(err)
	}
	item := <-ch
	expected := sha256.Sum256([]byte("public=42"))
	if item.Meta["commit"] != "" || item.Meta["digest"] != hex.EncodeToString(expected[:]) {
		t.Fatal("parent context replaced current source facts")
	}
}
