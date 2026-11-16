package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestBucketContextKeepsObjectBytesAndLiteralKeys(t *testing.T) {
	dir := t.TempDir()
	raw := []byte("AWS=AKIANAFGYOEYPXU1DSYP\n")
	name := "Ключ #?%20.env"
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
	c := model.NewCoverage()
	ctx, err := BucketContext(model.WithCoverage(context.Background(), c), dir, "s3://owned/prefix#?%20", 4096, 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	items := archiveItems(Filesystem(ctx, []string{dir}, nil, 4096))
	if len(items) != 1 {
		t.Fatalf("items=%+v", items)
	}
	sum := sha256.Sum256(raw)
	if items[0].Meta["digest"] != hex.EncodeToString(sum[:]) {
		t.Fatal("object byte digest missing")
	}
	u, err := url.Parse(items[0].Meta["source_url"].(string))
	if err != nil || u.Path != "/prefix#?%20/"+name || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("literal key was parsed as URL parameters")
	}
	result := model.NewResult(nil, c)
	if !result.Complete || len(result.Scope) != 2 || result.Scope[0].Kind != "bucket" || result.Scope[1].Kind != "bucket-selection" {
		t.Fatalf("scope=%+v", result)
	}
	data, _ := json.Marshal(result)
	if strings.Contains(string(data), dir) {
		t.Fatal("temporary sync directory leaked into source ledger")
	}
}

func TestBucketArchiveMembersRetainObjectProvenance(t *testing.T) {
	dir := t.TempDir()
	raw := makeZIP(t, map[string][]byte{"nested.env": []byte("AWS=AKIANAFGYOEYPXU1DSYP")})
	if err := os.WriteFile(filepath.Join(dir, "bundle.zip"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, err := BucketContext(context.Background(), dir, "gs://owned/prefix", 4096, 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	items := archiveItems(Filesystem(ctx, []string{dir}, nil, 4096))
	sum := sha256.Sum256(raw)
	if len(items) != 1 || items[0].Meta["source_url"] != "gs://owned/prefix/bundle.zip" || items[0].Meta["digest"] != hex.EncodeToString(sum[:]) {
		t.Fatal("archive member was mistaken for a cloud object")
	}
}

func TestBucketTargetRejectsAuthorityCredentialsButKeepsKeyPunctuation(t *testing.T) {
	for _, target := range []string{"s3://u:private@owned/prefix", "gs://owned?token=private", "s3:///prefix", "https://owned/prefix", "s3://owned\n/prefix"} {
		if ValidateBucketTarget(target) == nil {
			t.Fatal("invalid authority accepted")
		}
	}
	if err := ValidateBucketTarget("s3://owned/prefix#?%20/@literal"); err != nil {
		t.Fatal(err)
	}
}

func TestNestedAcquisitionOriginsDoNotKeepForeignObjectIdentifiers(t *testing.T) {
	repository, git := gitRepo(t)
	write(t, filepath.Join(repository, "prod.env"), "AWS=AKIANAFGYOEYPXU1DSYP")
	git("add", ".")
	git("commit", "-qm", "owned")
	c := model.NewCoverage()
	repoCtx, err := RepositoryContext(model.WithCoverage(context.Background(), c), repository, CloneOpts{URL: "https://owned.invalid/app.git"})
	if err != nil {
		t.Fatal(err)
	}
	downloaded := t.TempDir()
	write(t, filepath.Join(downloaded, "prod.env"), "AWS=AKIANAFGYOEYPXU1DSYP")
	bucketCtx, err := BucketContext(repoCtx, downloaded, "s3://owned/prefix", 4096, 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	items := archiveItems(Filesystem(bucketCtx, []string{downloaded}, nil, 4096))
	if len(items) != 1 || items[0].Meta["commit"] != nil && items[0].Meta["commit"] != "" || items[0].Meta["source_url"] != "s3://owned/prefix/prod.env" {
		t.Fatal("bucket object inherited a repository revision")
	}
	repoCtx, err = RepositoryContext(bucketCtx, repository, CloneOpts{URL: "https://owned.invalid/app.git"})
	if err != nil {
		t.Fatal(err)
	}
	items = archiveItems(Filesystem(repoCtx, []string{repository}, nil, 4096))
	if len(items) != 1 || items[0].Meta["digest"] != nil && items[0].Meta["digest"] != "" || items[0].Meta["source_url"] != "https://owned.invalid/app.git" {
		t.Fatal("repository inherited bucket bytes or locator")
	}
}

func TestBucketRelativeRootUsesLogicalScopes(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	write(t, "prod.env", "AWS=AKIANAFGYOEYPXU1DSYP")
	c := model.NewCoverage()
	ctx, err := BucketContext(model.WithCoverage(context.Background(), c), ".", "s3://owned/prefix", 4096, 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	items := archiveItems(Filesystem(ctx, []string{"."}, nil, 4096))
	if len(items) != 1 || items[0].Meta["source_url"] != "s3://owned/prefix/prod.env" {
		t.Fatal("relative root lost object identity")
	}
	data, _ := json.Marshal(model.NewResult(nil, c))
	if strings.Contains(string(data), dir) {
		t.Fatal("relative root leaked local scope")
	}
}

func TestValidateBucketTargetKeepsReleasedSchemeWordingWithoutEchoingTarget(t *testing.T) {
	const target = "ftp://user:hunter2secret@host/prefix"
	err := ValidateBucketTarget(target)
	if err == nil {
		t.Fatal("unsupported scheme accepted")
	}
	if !strings.Contains(err.Error(), "unsupported bucket URI") {
		t.Fatalf("released 1.4 wording lost: %q", err)
	}
	if strings.Contains(err.Error(), "hunter2secret") || strings.Contains(err.Error(), "ftp://") {
		t.Fatalf("error echoes the raw target: %q", err)
	}
}
