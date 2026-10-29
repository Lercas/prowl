// Package correlation joins observations by organization-scoped HMAC identity.
package correlation

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

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

// Read requires the new envelope and rejects plaintext exports for safe aggregation.
func Read(path string) (model.ScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.ScanResult{}, errors.New("cannot open report")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (32<<20)+1))
	if err != nil || len(data) > 32<<20 {
		return model.ScanResult{}, errors.New("report exceeds input budget")
	}
	var r model.ScanResult
	if json.Unmarshal(data, &r) != nil || r.SchemaVersion != "1.4" || r.Findings == nil || r.Count != len(r.Findings) {
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
			if f.Type == "results_truncated" || f.Type == "response_truncated" || f.Type == "item_too_large" {
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
	if r.Truncated {
		return false
	}
	for _, diagnostic := range r.Diagnostics {
		if diagnostic.Incomplete {
			return false
		}
	}
	for _, f := range r.Findings {
		if f.Type == "results_truncated" || f.Type == "response_truncated" || f.Type == "item_too_large" {
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
		if scope.Kind != "pipeline" && scope.Target != "" {
			hasTarget = true
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
			x.Reason = "Отсутствие в выбранном объёме не подтверждает отзыв credential"
		} else {
			x.Reason = "Неполный, отфильтрованный или несопоставимый скан"
		}
		out.Items = append(out.Items, x)
	}
	return out, nil
}
func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func Describe(err error) string { return fmt.Sprint(err) }
