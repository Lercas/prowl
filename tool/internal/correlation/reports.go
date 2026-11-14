// Package correlation joins observations by organization-scoped HMAC identity.
package correlation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/model"
)

type Observation struct {
	Report  int           `json:"report"`
	Finding model.Finding `json:"finding"`
}
type Group struct {
	SecretID       string        `json:"secret_id"`
	IdentityScope  string        `json:"identity_scope"`
	Relationship   string        `json:"relationship"`
	Observations   []Observation `json:"observations"`
	Links          []Link        `json:"links,omitempty"`
	LinksTruncated bool          `json:"links_truncated,omitempty"`
}
type Link struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Kind     string `json:"kind"`
	Evidence string `json:"evidence"`
}

type Summary struct {
	SchemaVersion string  `json:"schema_version"`
	Complete      bool    `json:"complete"`
	Groups        []Group `json:"groups"`
}

const maxReportBytes = 32 << 20
const maxReportsBytes = 128 << 20
const maxReports = 32
const maxArrayRows = 100000

// Read requires the released envelope and rejects explicitly revealed reports.
func Read(path string) (model.ScanResult, error) {
	r, _, _, err := readReport(path, maxReportBytes, maxArrayRows)
	return r, err
}

// ReadMany accounts actual bytes, so size changes cannot bypass the aggregate input budget.
func ReadMany(paths []string) ([]model.ScanResult, error) {
	return readMany(paths, maxReportsBytes, maxArrayRows)
}

func readMany(paths []string, byteBudget int64, rowBudget int) ([]model.ScanResult, error) {
	if len(paths) == 0 || len(paths) > maxReports {
		return nil, errors.New("expected 1 to 32 reports")
	}
	reports := make([]model.ScanResult, 0, len(paths))
	remaining := byteBudget
	remainingRows := rowBudget
	for _, path := range paths {
		if remaining <= 0 {
			return nil, errors.New("reports exceed aggregate input budget")
		}
		r, used, rows, err := readReport(path, min(int64(maxReportBytes), remaining), remainingRows)
		if err != nil {
			return nil, err
		}
		remaining -= used
		remainingRows -= rows
		reports = append(reports, r)
	}
	return reports, nil
}

func readReport(path string, limit int64, rowBudget int) (model.ScanResult, int64, int, error) {
	data, err := localfile.ReadRegular(path, limit)
	if err != nil {
		return model.ScanResult{}, 0, 0, errors.New("cannot read regular report within input budget")
	}
	rows, err := arrayRows(data, rowBudget)
	if err != nil {
		return model.ScanResult{}, int64(len(data)), rows, err
	}
	r, err := decodeReport(data)
	return r, int64(len(data)), rows, err
}

func decodeReport(data []byte) (model.ScanResult, error) {
	var r model.ScanResult
	if jsonstrict.UnmarshalContext(context.Background(), data, &r) != nil || r.SchemaVersion != "1.4" || r.Findings == nil || r.Count != len(r.Findings) {
		return r, errors.New("a Prowl 1.4 JSON envelope is required")
	}
	wantReason := "incomplete"
	if r.Complete {
		wantReason = "completed"
	}
	if r.CompletionReason != wantReason || r.Complete && !coverageConsistent(r) {
		return r, errors.New("contradictory scan completeness")
	}
	if r.SecretsRevealed {
		return r, errors.New("plaintext reports are not accepted")
	}
	for _, f := range r.Findings {
		if !consistentVerdict(f.Verified, f.Verification) {
			return r, errors.New("contradictory verification metadata")
		}
		for _, occurrence := range f.Occurrences {
			if !validVerificationDetail(occurrence.Verification) {
				return r, errors.New("contradictory verification metadata")
			}
		}
		if f.Context != nil || f.Redacted != "" && !strings.Contains(f.Redacted, "*") && !model.IsPEMKey(f.Redacted) {
			return r, errors.New("plaintext reports are not accepted")
		}
	}
	return r, nil
}
func Join(reports []model.ScanResult) (Summary, error) {
	out := Summary{SchemaVersion: "1.4", Complete: true, Groups: []Group{}}
	groups := map[string]*Group{}
	scope := ""
	for i, r := range reports {
		out.Complete = out.Complete && r.Complete && coverageConsistent(r)
		if !validHex(r.IdentityScope, 16) {
			return out, errors.New("report lacks identity scope")
		}
		if scope != "" && scope != r.IdentityScope {
			return out, errors.New("reports use different identity scopes")
		}
		scope = r.IdentityScope
		for _, f := range r.Findings {
			if model.IsIncompleteFinding(f) {
				continue
			}
			if !validHex(f.SecretID, 64) || !validHex(f.IdentityScope, 16) || !validHex(f.OccurrenceID, 64) {
				return out, errors.New("findings lack organization identity; initialize and reuse an identity key")
			}
			if scope != "" && scope != f.IdentityScope {
				return out, errors.New("reports use different identity scopes")
			}
			scope = f.IdentityScope
			g := groups[f.SecretID]
			if g == nil {
				g = &Group{SecretID: f.SecretID, IdentityScope: scope, Relationship: "same_secret_observed", Observations: []Observation{}}
				groups[f.SecretID] = g
			}
			g.Observations = append(g.Observations, Observation{i, f})
		}
	}
	for _, g := range groups {
		buckets := map[string]string{}
		seen := map[string]bool{}
		for _, o := range g.Observations {
			occurrences := append([]model.Occurrence{o.Finding.Occurrence()}, o.Finding.Occurrences...)
			for _, occurrence := range occurrences {
				if !validHex(occurrence.ID, 64) {
					return out, errors.New("occurrence lacks organization identity")
				}
				for _, key := range []string{"blob", "commit", "digest", "layer_digest"} {
					value := occurrence.Provenance[key]
					if !model.ValidImmutableMetadata(key, value) {
						continue
					}
					bucket := key + ":" + value
					if seen[occurrence.ID+"\x00"+bucket] {
						continue
					}
					seen[occurrence.ID+"\x00"+bucket] = true
					if first := buckets[bucket]; first != "" && first != occurrence.ID {
						if len(g.Links) < 256 {
							g.Links = append(g.Links, Link{first, occurrence.ID, "shared_" + key + "_metadata", value})
						} else {
							g.LinksTruncated = true
							out.Complete = false
						}
					} else if first == "" {
						buckets[bucket] = occurrence.ID
					}
				}
			}
		}
		out.Groups = append(out.Groups, *g)
	}
	sort.Slice(out.Groups, func(i, j int) bool { return out.Groups[i].SecretID < out.Groups[j].SecretID })
	return out, nil
}

func coverageConsistent(r model.ScanResult) bool {
	if r.Truncated || r.Stats.Skipped > 0 {
		return false
	}
	for _, diagnostic := range r.Diagnostics {
		if diagnostic.Incomplete {
			return false
		}
	}
	for _, f := range r.Findings {
		if model.IsIncompleteFinding(f) {
			return false
		}
	}
	return true
}

type Remediation struct {
	SecretID   string `json:"secret_id"`
	Presence   string `json:"presence"`
	Revocation string `json:"revocation"`
	Closed     bool   `json:"closed"`
	Reason     string `json:"reason,omitempty"`
}
type RemediationReport struct {
	SchemaVersion string        `json:"schema_version"`
	Comparable    bool          `json:"comparable"`
	Complete      bool          `json:"complete"`
	Items         []Remediation `json:"items"`
}

// Compare keeps absence and revocation separate. Absence cannot prove revocation:
// a report cannot recheck a key no longer present without plaintext retained elsewhere.
func Compare(before, after model.ScanResult) (RemediationReport, error) {
	joined, err := Join([]model.ScanResult{before, after})
	if err != nil {
		return RemediationReport{}, err
	}
	b, _ := json.Marshal(before.Scope)
	a, _ := json.Marshal(after.Scope)
	hasTarget := false
	for _, scope := range before.Scope {
		switch scope.Kind {
		case "filesystem", "stdin", "file-list", "git-worktree", "git-index", "git-history", "git-timeline", "mobile", "image", "agent-project", "agent-home":
			hasTarget = hasTarget || scope.Target != ""
		}
	}
	comparable := hasTarget && len(before.Scope) > 0 && string(b) == string(a) && !before.Filtered && !after.Filtered
	out := RemediationReport{"1.4", comparable, joined.Complete, []Remediation{}}
	for _, g := range joined.Groups {
		was := false
		var current []model.Finding
		for _, o := range g.Observations {
			if o.Report == 0 {
				was = true
			} else {
				current = append(current, o.Finding)
			}
		}
		if !was {
			continue
		}
		x := Remediation{SecretID: g.SecretID, Presence: "inconclusive", Revocation: "not_checked"}
		if len(current) > 0 {
			x.Presence = "present"
			allRejected := true
			for _, f := range current {
				checks := []*model.Verification{f.Verification}
				for _, occurrence := range f.Occurrences {
					checks = append(checks, occurrence.Verification)
				}
				for _, check := range checks {
					if check != nil && check.Status == "verified" {
						x.Revocation = "live"
						allRejected = false
					}
					if check == nil || check.Status != "invalid" {
						allRejected = false
					}
				}
			}
			if allRejected {
				x.Revocation = "provider_rejected"
			}
		} else if comparable && out.Complete {
			x.Presence = "absent_in_scope"
			x.Reason = "Absence from the selected scope does not prove the credential was revoked"
		} else {
			x.Reason = "Incomplete, filtered or incomparable scan"
		}
		out.Items = append(out.Items, x)
	}
	return out, nil
}
func validHex(s string, n int) bool {
	if len(s) != n || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func Describe(err error) string { return fmt.Sprint(err) }

// arrayRows bounds decoded slice amplification before allocating model structs.
// Object fields and string bytes remain bounded by the independent file-byte budget.
func arrayRows(data []byte, budget int) (int, error) {
	if err := jsonstrict.ValidateEncoding(data); err != nil {
		return 0, errors.New("invalid report JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	remaining := budget
	var visit func() error
	visit = func() error {
		token, err := dec.Token()
		if err != nil {
			return errors.New("invalid report JSON")
		}
		switch token {
		case json.Delim('{'):
			for dec.More() {
				if _, err := dec.Token(); err != nil {
					return errors.New("invalid report JSON")
				}
				if err := visit(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		case json.Delim('['):
			for dec.More() {
				if remaining <= 0 {
					return errors.New("reports exceed array row budget")
				}
				remaining--
				if err := visit(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		}
		return err
	}
	err := visit()
	return budget - remaining, err
}

func validVerificationDetail(detail *model.Verification) bool {
	if detail == nil {
		return true
	}
	if detail.CheckedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, detail.CheckedAt); err != nil {
			return false
		}
	}
	switch detail.Status {
	case "verified", "invalid", "unsupported", "error", "skipped":
		return true
	default:
		return false
	}
}

func consistentVerdict(verified *bool, detail *model.Verification) bool {
	if !validVerificationDetail(detail) {
		return false
	}
	if detail == nil {
		return true
	} // legacy booleans do not supply a detailed provider verdict
	switch detail.Status {
	case "verified":
		return verified != nil && *verified
	case "invalid":
		return verified != nil && !*verified
	default:
		return verified == nil
	}
}
