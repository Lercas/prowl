package scan

import (
	"github.com/Lercas/prowl/tool/internal/model"
)

const maxTimelineSteps = 10000000

type timelineGroup struct {
	fingerprint string
	record      *model.GitRecord
	blobs       map[string]bool
	indices     []int
}

type timelineState struct {
	blob           string
	known, present bool
	start          string
}

// FinalizeGitTimeline runs after all workers and requested ML have completed,
// before display suppression, occurrence caps or fingerprint deduplication.
// Absence is evidence about this detector/ML configuration, not key revocation.
func FinalizeGitTimeline(findings []model.Finding) []model.Finding {
	groups := make(map[*model.GitHistoryGraph]map[string]*timelineGroup)
	complete := true
	for i, f := range findings {
		if model.IsIncompleteFinding(f) {
			complete = false
		}
		if f.GitRecord == nil || f.Fingerprint == "" || model.IsIncompleteFinding(f) {
			continue
		}
		record := f.GitRecord
		if groups[record.Graph] == nil {
			groups[record.Graph] = make(map[string]*timelineGroup)
		}
		group := groups[record.Graph][f.Fingerprint]
		if group == nil {
			group = &timelineGroup{fingerprint: f.Fingerprint, record: record, blobs: make(map[string]bool)}
			groups[record.Graph][f.Fingerprint] = group
		}
		group.blobs[record.Object.Blob] = true
		group.indices = append(group.indices, i)
	}
	steps := 0
	for graph, byKey := range groups {
		if len(graph.Commits) > maxTimelineSteps/max(1, len(byKey)) {
			steps = maxTimelineSteps + 1
			break
		}
		steps += len(graph.Commits) * len(byKey)
	}
	limited := steps > maxTimelineSteps
	partial := false
	for graph, byKey := range groups {
		for _, group := range byKey {
			timeline := &model.GitTimeline{Complete: complete && graph.Complete && !limited && !graph.ObservationLimited.Load(), Basis: "detector_observations_first_parent", Head: graph.Head, Appearances: []model.GitCommit{}, Removals: []model.GitRemoval{}}
			if !limited {
				resolveTimeline(graph, group, timeline)
			}
			partial = partial || !timeline.Complete
			for _, index := range group.indices {
				findings[index].Git = timeline
				findings[index].GitRecord = nil
			}
		}
	}
	if limited || partial && complete {
		findings = append(findings, model.Finding{Detector: "scan", Type: "response_truncated", Severity: "info", Stage: "git timeline", Rationale: "git timeline coverage or resolution limit prevents complete lifecycle metadata"})
	}
	for i := range findings {
		findings[i].GitRecord = nil
	}
	return findings
}

func resolveTimeline(graph *model.GitHistoryGraph, group *timelineGroup, timeline *model.GitTimeline) {
	states := make(map[string]timelineState, len(graph.Commits))
	commits := make(map[string]model.GitCommit, len(graph.Commits))
	for _, commit := range graph.Commits {
		commits[commit.Hash] = commit
	}
	for _, commit := range graph.Commits {
		previous := timelineState{known: graph.Complete}
		if len(commit.Parents) > 0 {
			previous = states[commit.Parents[0]]
		}
		current := previous
		if blob, changed := graph.Changes[commit.Hash][group.record.Object.Path]; changed {
			current = timelineState{blob: blob}
			switch {
			case blob == "":
				current.known = true
			case group.blobs[blob] || gitObserved(graph, group.fingerprint, model.GitObject{Path: group.record.Object.Path, Blob: blob}):
				current.known, current.present = true, true
			default:
				inspected, ok := graph.Inspected.Load(model.GitObject{Path: group.record.Object.Path, Blob: blob})
				current.known = ok && inspected == true
			}
		}
		if !current.known {
			timeline.Complete = false
		}
		if current.known && current.present {
			if previous.known && !previous.present {
				timeline.Appearances = append(timeline.Appearances, commit)
				current.start = commit.Hash
			} else if previous.known && previous.present {
				current.start = previous.start
			}
		}
		if previous.known && previous.present && current.known && !current.present {
			removal := model.GitRemoval{Commit: commit, IntroducedIn: previous.start}
			if start, ok := commits[previous.start]; ok {
				seconds := commit.CommittedAt.Unix() - start.CommittedAt.Unix()
				if seconds >= 0 {
					removal.ExposureSeconds = &seconds
				}
			}
			timeline.Removals = append(timeline.Removals, removal)
		}
		states[commit.Hash] = current
	}
	if state, ok := states[graph.Head]; ok && state.known && (state.present || timeline.Complete) {
		present := state.present
		timeline.InHEAD = &present
	}
	if !timeline.Complete {
		timeline.Removals = []model.GitRemoval{}
	}
	// Dates can run backwards and branch order is not chronological. Events keep
	// their graph order; sorting only the report's shared observations is unnecessary.
}

func gitObserved(graph *model.GitHistoryGraph, fingerprint string, object model.GitObject) bool {
	_, ok := graph.Observations.Load(model.GitObservation{Fingerprint: fingerprint, Object: object})
	return ok
}

const maxGitObservations = 1000000

func observeGitCandidate(record *model.GitRecord, typ, path, value string) {
	if record.Graph.ObservationCount.Add(1) > maxGitObservations {
		record.Graph.ObservationLimited.Store(true)
		return
	}
	record.Graph.Observations.Store(model.GitObservation{Fingerprint: model.ComputeFingerprint(typ, path, value), Object: record.Object}, true)
}
