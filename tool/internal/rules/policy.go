package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// PolicyDigest includes extraction semantics omitted by ordinary JSON serialization.
func (e *Engine) PolicyDigest() (string, error) {
	type policyTemplate struct {
		Template *Template
		Groups   []int
	}
	templates := make([]policyTemplate, 0, len(e.templates))
	for _, t := range e.templates {
		groups := make([]int, 0, len(t.Extractors))
		for _, extractor := range t.Extractors {
			group := extractor.Group
			if group == 0 && !extractor.groupSet {
				group = 1
			}
			groups = append(groups, group)
		}
		templates = append(templates, policyTemplate{t, groups})
	}
	b, err := json.Marshal(struct {
		Bundled   bool
		Templates []policyTemplate
	}{e.bundled, templates})
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
