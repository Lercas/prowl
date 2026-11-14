package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

func TestIndexedScanCLIAndDiffEndToEnd(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	t.Setenv("PROWL_HOME", filepath.Join(directory, "home"))
	const oldKey = "AKIANAFGYOEYPXU1DSYP"
	const newKey = "AKIAQ7MR9V8X2N5P3L6T"
	file := filepath.Join(directory, "app.env")
	if err := os.WriteFile(file, []byte("FIRST="+oldKey+"\nSECOND="+oldKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(directory, ".private-index")
	output := filepath.Join(t.TempDir(), "report.json")
	args := []string{".", "--index", index, "--scope", "repo:app", "--format", "json", "--output", output, "--disable", "aws_access_key_id", "--silence"}
	if code := cmdScan(args); code != 0 {
		t.Fatalf("first indexed scan returned %d", code)
	}
	_, findings := readBucketReport(t, output)
	if len(findings) != 0 {
		t.Fatal("display suppression was ignored")
	}
	store, err := secretindex.Open(t.Context(), index, true)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := store.Secrets(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || secrets[0].LocationCount != 2 {
		t.Fatalf("index dropped pre-display occurrences: %+v", secrets)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("FIRST="+oldKey+"\nSECOND="+newKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := cmdScan(args); code != 0 {
		t.Fatalf("second indexed scan returned %d", code)
	}
	diffOutput := filepath.Join(t.TempDir(), "diff.json")
	if code := cmdIndex("diff", []string{"--index", index, "--scope", "repo:app", "--format", "json", "--output", diffOutput}); code != 0 {
		t.Fatal("automatic diff failed")
	}
	var diff secretindex.Diff
	raw, err := os.ReadFile(diffOutput)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &diff); err != nil {
		t.Fatal(err)
	}
	if diff.From.ID != 1 || diff.To.ID != 2 || len(diff.NewValues) != 1 || len(diff.NotSeenValues) != 0 || len(diff.NewLocations) != 1 || len(diff.NotSeenLocations) != 1 {
		t.Fatalf("incorrect CLI diff: %+v", diff)
	}
	viewOutput := filepath.Join(t.TempDir(), "index.json")
	if code := runCLI([]string{"index", "--index", index, "--format", "json", "--output", viewOutput}); code != 0 {
		t.Fatal("index dispatcher failed")
	}
	raw, err = os.ReadFile(viewOutput)
	if err != nil {
		t.Fatal(err)
	}
	var view indexView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Scans) != 2 || len(view.Secrets) != 2 || !view.Scans[0].Complete || !view.Scans[1].Complete {
		t.Fatal("complete snapshots not persisted")
	}
	for _, name := range []string{viewOutput, filepath.Join(index, "index.sqlite")} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(oldKey)) || bytes.Contains(raw, []byte(newKey)) {
			t.Fatal("persisted index/report contains a raw credential")
		}
	}
}

func TestIndexFlagsAndOutputIsolation(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	t.Setenv("PROWL_HOME", filepath.Join(directory, "home"))
	index := filepath.Join(directory, "private-index")
	for _, args := range [][]string{{"--index", index}, {"--scope", "scope"}, {"--index", index, "--scope", "scope", "--output", filepath.Join(index, "key")}, {"--index", index, "--scope", "scope", "--write-baseline", filepath.Join(index, "index.sqlite")}} {
		if code := cmdScan(args); code != 2 {
			t.Fatal("unsafe or ambiguous index flags accepted")
		}
	}
	if _, err := os.Lstat(index); !os.IsNotExist(err) {
		t.Fatal("refused flag/output combination created an index")
	}
	if code := cmdIndex("index", []string{"--index", index}); code != 2 {
		t.Fatal("absent index inspection succeeded")
	}
	if _, err := os.Lstat(index); !os.IsNotExist(err) {
		t.Fatal("inspection created an absent index")
	}
	store, err := secretindex.Open(t.Context(), index, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(index, "key"))
	if err != nil {
		t.Fatal(err)
	}
	if code := cmdIndex("index", []string{"--index", index, "--output", filepath.Join(index, "key")}); code != 2 {
		t.Fatal("index query overwrote its own key")
	}
	after, err := os.ReadFile(filepath.Join(index, "key"))
	if err != nil || !bytes.Equal(key, after) {
		t.Fatal("protected index key changed")
	}
	alias := filepath.Join(directory, "alias")
	if err := os.Symlink(index, alias); err == nil {
		if err := validateIndexOutputs(commonFlags{indexDir: index, output: filepath.Join(alias, "key")}); err == nil {
			t.Fatal("output alias bypassed index protection")
		}
	}
}

func TestIncompleteIndexedScanCannotBecomeDiffBaseline(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	t.Setenv("PROWL_HOME", filepath.Join(directory, "home"))
	index := filepath.Join(directory, "index")
	output := filepath.Join(t.TempDir(), "partial.json")
	if code := cmdScan([]string{"missing.env", "--index", index, "--scope", "app", "--format", "json", "--output", output}); code != 2 {
		t.Fatal("unreadable source certified complete")
	}
	store, err := secretindex.Open(t.Context(), index, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	scans, err := store.Scans(t.Context(), "app")
	if err != nil || len(scans) != 1 || scans[0].Complete {
		t.Fatal("incomplete source became a complete index snapshot")
	}
	if code := cmdIndex("diff", []string{"--index", index, "--scope", "app"}); code != 2 {
		t.Fatal("automatic diff accepted incomplete baseline")
	}
}

func TestEmptyCICDIndexSnapshotRemainsIncomplete(t *testing.T) {
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(false) })
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/app/actions/runs" {
			_, _ = io.WriteString(w, `{"workflow_runs":[]}`)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	directory := t.TempDir()
	t.Chdir(directory)
	t.Setenv("PROWL_HOME", filepath.Join(directory, "home"))
	t.Setenv("GITHUB_API", api.URL)
	t.Setenv("GITHUB_TOKEN", "test-command-token")
	index := filepath.Join(directory, "index")
	output := filepath.Join(t.TempDir(), "ci.json")
	if code := cmdCICD([]string{"github:acme/app", "--logs-only", "--index", index, "--scope", "ci:app", "--format", "json", "--output", output}); code != 2 {
		t.Fatal("empty CI collection succeeded")
	}
	store, err := secretindex.Open(t.Context(), index, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	scans, err := store.Scans(t.Context(), "")
	if err != nil || len(scans) != 1 || scans[0].Complete {
		t.Fatal("empty CI collection became complete absence evidence")
	}
}

type shortIndexWriter struct{}

func (shortIndexWriter) Write([]byte) (int, error) { return 0, nil }

func TestIndexPrettyOutputSanitizesPathsAndPropagatesWriteErrors(t *testing.T) {
	payload := indexView{Secrets: []secretindex.Secret{{ValueID: "owned", LocationCount: 1, Locations: []secretindex.Location{{Path: "a\x1b[31m.env", Source: "code", Type: "owned"}}}}}
	var b bytes.Buffer
	if err := writeIndexPayload(&b, payload, "pretty"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\x1b") || !strings.Contains(b.String(), "locations ever seen: 1") {
		t.Fatal("pretty index report unsafe or unreadable")
	}
	if err := writeIndexPayload(shortIndexWriter{}, payload, "pretty"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short index report write ignored")
	}
	if err := writeIndexPayload(shortIndexWriter{}, payload, "json"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short JSON index report write ignored")
	}
}

func TestAutomaticIndexDiffDoesNotSkipNewestIncompleteScan(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "index")
	store, err := secretindex.Open(t.Context(), directory, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, complete := range []bool{true, true, false} {
		if _, err := store.Record(t.Context(), "scope", time.Now(), complete, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "diff.json")
	if code := cmdIndex("diff", []string{"--index", directory, "--scope", "scope", "--output", output}); code != 2 {
		t.Fatal("automatic diff silently skipped a newer incomplete scan")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("refused comparison created a report")
	}
	if code := cmdIndex("diff", []string{"1", "2", "--index", directory, "--scope", "scope", "--output", output}); code != 0 {
		t.Fatal("explicit historical complete comparison failed")
	}
}
