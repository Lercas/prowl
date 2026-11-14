package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestFilesystemPolicySkipsRemainCompleteAndObservable(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"keep.env": "ordinary text", "skip.env": "excluded", "asset.png": "ignored extension", "binary.env": "\x00\x00\x00"} {
		write(t, filepath.Join(dir, name), body)
	}
	if err := os.Mkdir(filepath.Join(dir, "node_modules"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("keep.env", filepath.Join(dir, "link.env")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	c := model.NewCoverage()
	items := archiveItems(Filesystem(model.WithCoverage(t.Context(), c), []string{dir}, []string{"skip.env"}, 1024))
	if len(items) != 1 || items[0].Error != nil || filepath.Base(items[0].Path) != "keep.env" {
		t.Fatalf("selection changed: %+v", items)
	}
	r := model.NewResult(nil, c)
	if !r.Complete || r.Stats.Skipped != 0 || r.Filtered {
		t.Fatal("policy skips became incomplete or finding suppression")
	}
	codes := map[string]bool{}
	for _, d := range r.Diagnostics {
		codes[d.Code] = true
	}
	for _, code := range []string{"excluded_path", "unsupported_extension", "binary", "symlink", "excluded_directory"} {
		if !codes[code] {
			t.Errorf("missing diagnostic %s", code)
		}
	}
}

func TestExcludedArchiveMemberIsObservableWithoutReadingIt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bundle.zip")
	writeZIPFile(t, p, map[string][]byte{"skip.env": []byte("excluded secret"), "keep.env": []byte("ordinary text")})
	c := model.NewCoverage()
	items := archiveItems(Filesystem(model.WithCoverage(t.Context(), c), []string{p}, []string{"skip.env"}, 1024))
	r := model.NewResult(nil, c)
	if len(items) != 1 || items[0].Text != "ordinary text" || !r.Complete || len(r.Diagnostics) != 1 || r.Diagnostics[0].Code != "excluded_path" {
		t.Fatal("excluded archive member lost its policy diagnostic or was emitted")
	}
}

func TestGitScopesRetainRequestedSelectionEvenWithoutItems(t *testing.T) {
	dir, git := gitRepo(t)
	write(t, filepath.Join(dir, "input.env"), "selected content")
	git("add", "input.env")
	git("commit", "-qm", "fixture")
	t.Chdir(dir)
	for name, acquire := range map[string]func(context.Context) <-chan model.Item{
		"git-history":  func(ctx context.Context) <-chan model.Item { return GitHistoryBlobs(ctx, dir, nil, 1024) },
		"git-timeline": func(ctx context.Context) <-chan model.Item { return GitTimelineBlobs(ctx, dir, nil, 1024) },
		"git-index":    func(ctx context.Context) <-chan model.Item { return GitIndexFilesIn(ctx, dir, nil, nil, 1024) },
		"git-worktree": func(ctx context.Context) <-chan model.Item { return GitWorktreeFilesIn(ctx, dir, nil, nil, 1024) },
		"file-list":    func(ctx context.Context) <-chan model.Item { return FilesFromListFiltered(ctx, nil, nil, 1024) },
	} {
		t.Run(name, func(t *testing.T) {
			c := model.NewCoverage()
			for it := range acquire(model.WithCoverage(t.Context(), c)) {
				if it.Error != nil {
					t.Fatal(it.Error)
				}
			}
			scopes := model.NewResult(nil, c).Scope
			if len(scopes) != 1 || scopes[0].Kind != name || scopes[0].Target != dir {
				t.Fatalf("lost requested scope: %+v", scopes)
			}
		})
	}
	var policies []string
	for _, paths := range [][]string{{}, {"input.env"}, {"another.env"}} {
		c := model.NewCoverage()
		for range GitIndexFilesIn(model.WithCoverage(t.Context(), c), dir, paths, nil, 1024) {
		}
		policies = append(policies, model.NewResult(nil, c).Scope[0].Policy)
	}
	if policies[0] == policies[1] || policies[1] == policies[2] {
		t.Fatal("distinct selected inputs share a scope policy")
	}
}

func TestMobileImageAndAgentAcquisitionRegisterScopes(t *testing.T) {
	for _, mode := range []string{"mobile", "image", "agent-project"} {
		t.Run(mode, func(t *testing.T) {
			c := model.NewCoverage()
			ctx := model.WithCoverage(t.Context(), c)
			dir := t.TempDir()
			switch mode {
			case "mobile":
				p := makeAPK(t, map[string][]byte{"input.txt": []byte("ordinary text")})
				ch, err := Extract(ctx, p, defaultOpts())
				if err != nil {
					t.Fatal(err)
				}
				for range ch {
				}
			case "image":
				// An explicit missing local tar must register selection without contacting a registry.
				if _, _, err := Image(ctx, filepath.Join(dir, "missing.tar"), ImageTar, 1024, 0, nil); err == nil {
					t.Fatal("expected local acquisition error")
				}
			case "agent-project":
				for range AgentSurface(ctx, AgentOptions{Projects: []string{dir}, MaxBytes: 1024}) {
				}
			}
			scopes := model.NewResult(nil, c).Scope
			if len(scopes) != 1 || scopes[0].Kind != mode || len(scopes[0].Policy) != 64 {
				t.Fatalf("lost source scope: %+v", scopes)
			}
		})
	}
}
