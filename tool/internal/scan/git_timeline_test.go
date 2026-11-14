package scan

import (
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
)

func timelineFixture() (*model.GitHistoryGraph, []model.Finding) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g := &model.GitHistoryGraph{Head: "c4", Complete: true, Changes: map[string]map[string]string{
		"c1": {"prod.env": "b1"}, "c2": {"prod.env": "b2"}, "c3": {"prod.env": "clean"}, "c4": {"prod.env": "b1"},
	}}
	for i, hash := range []string{"c1", "c2", "c3", "c4"} {
		c := model.GitCommit{Hash: hash, Author: "Owned fixture", CommittedAt: start.Add(time.Duration(i) * time.Hour), AuthoredAt: start}
		if i > 0 {
			c.Parents = []string{g.Commits[i-1].Hash}
		}
		g.Commits = append(g.Commits, c)
	}
	g.Inspected.Store(model.GitObject{Path: "prod.env", Blob: "clean"}, true)
	fs := []model.Finding{}
	for _, blob := range []string{"b1", "b2"} {
		fs = append(fs, model.Finding{Type: "aws_access_key_id", Fingerprint: "same-value", GitRecord: &model.GitRecord{Graph: g, Object: model.GitObject{Path: "prod.env", Blob: blob}}})
	}
	return g, fs
}

func TestGitTimelineUnionsValuesAcrossBlobEditsAndReappearance(t *testing.T) {
	_, fs := timelineFixture()
	fs = FinalizeGitTimeline(fs)
	a := fs[0].Git
	if !a.Complete || a.InHEAD == nil || !*a.InHEAD || len(a.Appearances) != 2 || len(a.Removals) != 1 {
		t.Fatal("unexpected value lifecycle")
	}
	if a.Appearances[0].Hash != "c1" || a.Appearances[1].Hash != "c4" || a.Removals[0].Commit.Hash != "c3" || a.Removals[0].IntroducedIn != "c1" || a.Removals[0].ExposureSeconds == nil || *a.Removals[0].ExposureSeconds != 7200 {
		t.Fatal("ordinary blob edit broke exposure interval")
	}
	if fs[1].Git != a || fs[0].GitRecord != nil {
		t.Fatal("shared timeline or private graph cleanup failed")
	}
}

func TestGitTimelineUnknownSnapshotAndDiagnosticsNeverProveRemoval(t *testing.T) {
	for _, mode := range []string{"uninspected", "diagnostic", "shallow"} {
		t.Run(mode, func(t *testing.T) {
			g, fs := timelineFixture()
			g.Head = "c3"
			switch mode {
			case "uninspected":
				g.Inspected.Delete(model.GitObject{Path: "prod.env", Blob: "clean"})
			case "diagnostic":
				fs = append(fs, model.Finding{Type: "source_error"})
			case "shallow":
				g.Complete = false
			}
			fs = FinalizeGitTimeline(fs)
			a := fs[0].Git
			if a.Complete || a.InHEAD != nil || len(a.Removals) != 0 {
				t.Fatal("unknown history became confirmed absence")
			}
		})
	}
}

func TestGitTimelineBranchesAndMergeUseFirstParentEdges(t *testing.T) {
	g, fs := timelineFixture()
	g.Commits = g.Commits[:3]
	g.Commits[2].Parents = []string{"c1"} // separate branch removes the value
	merge := model.GitCommit{Hash: "merge", Parents: []string{"c3", "c2"}, CommittedAt: g.Commits[2].CommittedAt.Add(time.Hour)}
	g.Commits = append(g.Commits, merge)
	g.Head = "merge"
	g.Changes["merge"] = map[string]string{"prod.env": "b2"}
	fs = FinalizeGitTimeline(fs)
	a := fs[0].Git
	if len(a.Appearances) != 2 || a.Appearances[1].Hash != "merge" || a.InHEAD == nil || !*a.InHEAD {
		t.Fatal("merge reappearance or branch isolation failed")
	}
}

func TestGitTimelineWorkerMarksOnlyCompleteLiteralSnapshot(t *testing.T) {
	g, _ := timelineFixture()
	object := model.GitObject{Path: "owned.env", Blob: "owned"}
	r := &model.GitRecord{Graph: g, Object: object}
	p := New(Options{Detector: detector(t)})
	fs := p.Findings(t.Context(), model.Item{Path: object.Path, Source: "code", Text: "AWS=AKIANAFGYOEYPXU1DSYP", Meta: map[string]any{"git_history": r}})
	if len(fs) != 1 || fs[0].GitRecord != r {
		t.Fatal("worker lost source graph provenance")
	}
	if value, ok := g.Inspected.Load(object); !ok || value != true {
		t.Fatal("completed literal snapshot not recorded")
	}
}

func TestGitTimelineMLSuppressionCannotCreateRemoval(t *testing.T) {
	g, fs := timelineFixture()
	g.Commits = g.Commits[:2]
	g.Head = "c2"
	record := fs[1].GitRecord
	p := New(Options{Detector: detector(t), ML: fixedMLScorer{results: []mlscore.Result{{Score: 0}}, threshold: 0.3}})
	item := model.Item{Source: "code", Path: "prod.env", Text: "AWS=AKIANAFGYOEYPXU1DSYP", Meta: map[string]any{"git_history": record}}
	if out := p.Findings(t.Context(), item); len(out) != 0 {
		t.Fatal("fixture was not suppressed by ML")
	}
	// The retained observation has the real fingerprint computed by the worker.
	fs = fs[:1]
	fs[0].Fingerprint = model.ComputeFingerprint("aws_access_key_id", "prod.env", "AKIANAFGYOEYPXU1DSYP")
	fs = FinalizeGitTimeline(fs)
	if fs[0].Git.InHEAD == nil || !*fs[0].Git.InHEAD || len(fs[0].Git.Removals) != 0 {
		t.Fatal("ML display suppression became Git removal")
	}
}

func TestGitTimelineResourceLimitCannotConfirmAbsence(t *testing.T) {
	g, fs := timelineFixture()
	g.Head = "c3"
	g.ObservationCount.Store(maxGitObservations)
	New(Options{}).observeGitCandidate(fs[0].GitRecord, "owned", "prod.env", "opaque")
	fs = FinalizeGitTimeline(fs)
	if fs[0].Git.Complete || fs[0].Git.InHEAD != nil || len(fs[0].Git.Removals) != 0 || !model.IsIncompleteFinding(fs[len(fs)-1]) {
		t.Fatal("observation limit became confirmed removal")
	}
}

func TestGitTimelineReversedCommitClockOmitsExposureDuration(t *testing.T) {
	g, fs := timelineFixture()
	g.Commits[2].CommittedAt = g.Commits[0].CommittedAt.Add(-time.Hour)
	fs = FinalizeGitTimeline(fs)
	if len(fs[0].Git.Removals) != 1 || fs[0].Git.Removals[0].ExposureSeconds != nil {
		t.Fatal("negative exposure duration reported")
	}
}
