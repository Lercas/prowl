package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"sort"

	"gopkg.in/yaml.v3"
)

const maxPolicyBytes = 32 << 20
const maxPolicyEntries = 100000

// Policy owns an immutable copy of the declared config and its effective allowlist.
// It never retains the source file bytes or exposes mutable config fields.
type Policy struct {
	config      Config
	digest      string
	restrictive bool
}

func (p *Policy) PolicyID() string                { return p.digest }
func (p *Policy) Allowed(value, path string) bool { return p.config.Allowed(value, path) }
func (p *Policy) Restrictive() bool               { return p.restrictive }

// Snapshot runs after rule imports/merges and captures the compiled allowlist too.
// Count input before copying or serializing a programmatically assembled config.
func (c *Config) Snapshot() (*Policy, error) {
	bytesLeft, entriesLeft := maxPolicyBytes, maxPolicyEntries
	add := func(s string) bool { bytesLeft -= len(s); entriesLeft--; return bytesLeft >= 0 && entriesLeft >= 0 }
	if c == nil {
		c = &Config{}
	}
	for _, group := range [][]string{c.Exclude, c.Detectors.Enable, c.Detectors.Disable, c.Allowlist.Paths, c.Allowlist.Values, c.Allowlist.Regexes, c.Allowlist.StopWords, c.allowPaths, c.allowStopWords} {
		for _, s := range group {
			if !add(s) {
				return nil, errors.New("configuration policy budget exceeded")
			}
		}
	}
	for _, r := range c.Detectors.Custom {
		for _, s := range []string{r.ID, r.Regex, r.Category} {
			if !add(s) {
				return nil, errors.New("configuration policy budget exceeded")
			}
		}
	}
	for s := range c.allowVal {
		if !add(s) {
			return nil, errors.New("configuration policy budget exceeded")
		}
	}
	for _, r := range c.allowRe {
		if r == nil {
			return nil, errors.New("invalid configuration policy")
		}
		if !add(r.String()) {
			return nil, errors.New("configuration policy budget exceeded")
		}
	}
	for _, s := range []string{c.Output.Format, c.Output.FailOn, c.Performance.VerifyTimeout, c.Limits.CloneTimeout} {
		if !add(s) {
			return nil, errors.New("configuration policy budget exceeded")
		}
	}
	copy := *c
	copy.Exclude = slices.Clone(c.Exclude)
	copy.Detectors.Enable = slices.Clone(c.Detectors.Enable)
	copy.Detectors.Disable = slices.Clone(c.Detectors.Disable)
	copy.Detectors.Custom = slices.Clone(c.Detectors.Custom)
	copy.Allowlist.Paths = slices.Clone(c.Allowlist.Paths)
	copy.Allowlist.Values = slices.Clone(c.Allowlist.Values)
	copy.Allowlist.Regexes = slices.Clone(c.Allowlist.Regexes)
	copy.Allowlist.StopWords = slices.Clone(c.Allowlist.StopWords)
	if c.Output.Redact != nil {
		value := *c.Output.Redact
		copy.Output.Redact = &value
	}
	copy.allowVal = maps.Clone(c.allowVal)
	copy.allowPaths = slices.Clone(c.allowPaths)
	copy.allowStopWords = slices.Clone(c.allowStopWords)
	copy.allowRe = slices.Clone(c.allowRe)
	copy.loadedAt = ""
	copy.raw = nil
	var values, regexes []string
	for value, active := range copy.allowVal {
		if active {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	for _, r := range copy.allowRe {
		regexes = append(regexes, r.String())
	}
	// YAML preserves invalid UTF-8 binary strings, unlike JSON string replacement.
	data, err := yaml.Marshal(struct {
		Definition                        *Config
		Values, Paths, StopWords, Regexes []string
	}{&copy, values, copy.allowPaths, copy.allowStopWords, regexes})
	if err != nil {
		return nil, err
	}
	if len(data) > maxPolicyBytes {
		return nil, errors.New("configuration policy budget exceeded")
	}
	sum := sha256.Sum256(data)
	restrictive := len(copy.Detectors.Enable)+len(copy.Detectors.Disable)+len(copy.Allowlist.Paths)+len(copy.Allowlist.Values)+len(copy.Allowlist.Regexes)+len(copy.Allowlist.StopWords) > 0
	return &Policy{config: copy, digest: hex.EncodeToString(sum[:]), restrictive: restrictive}, nil
}
