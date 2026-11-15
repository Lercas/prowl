package main

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strconv"

	"github.com/Lercas/prowl/tool/internal/model"
)

const maxReportOccurrences = 2048
const occurrenceAggregationStage = "occurrence aggregation"

// An accumulator owns its slice and bounds both the retained list and identity map.
// It is created only for duplicates or findings already carrying occurrences.
type occurrenceAccumulator struct {
	items   []model.Occurrence
	seen    map[string]int
	limited bool
}

func occurrenceKey(o model.Occurrence) string {
	if o.ID != "" {
		return "id:" + o.ID
	}
	// Keyless scans still distinguish source evidence and immutable revision IDs.
	// Verification is an observation about the occurrence, not its identity.
	h := sha256.New()
	var length [8]byte
	part := func(value string) {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(value))
	}
	// Preserve raw locator bytes, including filenames that are not valid UTF-8.
	for _, value := range []string{o.Source, o.Path, strconv.Itoa(o.Line), strconv.Itoa(o.Col), strconv.Itoa(len(o.Evidence))} {
		part(value)
	}
	for _, e := range o.Evidence {
		for _, value := range []string{e.Path, strconv.Itoa(e.Start), strconv.Itoa(e.End), strconv.Itoa(e.Line), strconv.Itoa(e.Col), e.Transform} {
			part(value)
		}
	}
	keys := make([]string, 0, len(o.Provenance))
	for key := range o.Provenance {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	part(strconv.Itoa(len(keys)))
	for _, key := range keys {
		part(key)
		part(o.Provenance[key])
	}
	return "source:" + string(h.Sum(nil))
}

func (a *occurrenceAccumulator) add(o model.Occurrence, key string) {
	// Without a report ID, identical visible coordinates do not prove the same
	// physical occurrence (e.g. repeated TAR entries). Retain each observation.
	if o.ID == "" {
		if len(a.items) == maxReportOccurrences {
			a.limited = true
		} else {
			a.items = append(a.items, o)
		}
		return
	}
	if a.seen == nil {
		a.seen = make(map[string]int)
	}
	if i, found := a.seen[key]; found {
		if o.PublicKeyAudit != nil && (a.items[i].PublicKeyAudit == nil || o.PublicKeyAudit.Status == "excess_permissions") {
			a.items[i].PublicKeyAudit = o.PublicKeyAudit
		}
		if o.Verification != nil && (a.items[i].Verification == nil || o.Verification.Status == "verified") {
			a.items[i].Verification = o.Verification
		}
		return
	}
	if len(a.items) == maxReportOccurrences {
		a.limited = true
		return
	}
	a.seen[key] = len(a.items)
	a.items = append(a.items, o)
}

func (a *occurrenceAccumulator) addFinding(f model.Finding) {
	primary := f.Occurrence()
	if len(f.Occurrences) == 0 {
		a.add(primary, "id:"+primary.ID)
		return
	}
	primaryKey := occurrenceKey(primary)
	hasPrimary := false
	for _, o := range f.Occurrences {
		key := occurrenceKey(o)
		hasPrimary = hasPrimary || key == primaryKey
		a.add(o, key)
	}
	// An aggregate's top-level verdict summarizes the group. Its retained primary
	// occurrence is authoritative about that source position's own verification.
	if !hasPrimary {
		a.add(primary, primaryKey)
	}
}

func combineFindingSummary(chosen *model.Finding, other model.Finding) {
	if other.PublicKeyAudit != nil && (chosen.PublicKeyAudit == nil || other.PublicKeyAudit.Status == "excess_permissions") {
		chosen.PublicKeyAudit = other.PublicKeyAudit
	}
	if other.Verified != nil && *other.Verified && (chosen.Verified == nil || !*chosen.Verified || chosen.Verification == nil) {
		chosen.Verified, chosen.Verification, chosen.Rationale = other.Verified, other.Verification, other.Rationale
	}
	// Display provenance may prefer the final image, but it cannot weaken a gate.
	if model.SeverityOrder[other.Severity] > model.SeverityOrder[chosen.Severity] {
		chosen.Severity = other.Severity
	}
	if other.Confidence > chosen.Confidence {
		chosen.Confidence = other.Confidence
	}
}
