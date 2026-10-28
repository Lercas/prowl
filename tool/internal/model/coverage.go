package model

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
)

// Diagnostic is scan metadata, never a synthetic secret or a raw error string.
type Diagnostic struct {
	Code       string `json:"code"`
	Path       string `json:"path,omitempty"`
	Incomplete bool   `json:"incomplete"`
}

type ScanStats struct {
	Processed       int64 `json:"processed"`
	Bytes           int64 `json:"bytes"`
	Skipped         int64 `json:"skipped"`
	DiagnosticCount int64 `json:"diagnostic_count"`
}

// Coverage belongs to one scan and is shared by its source and pipeline workers.
type Coverage struct {
	mu              sync.Mutex
	stats           ScanStats
	diagnostics     []Diagnostic
	complete        bool
	scopes          []Scope
	filtered        bool
	identityScope   string
	secretsRevealed bool
	policyKey       []byte
}

func NewCoverage() *Coverage { return &Coverage{complete: true} }

type coverageKey struct{}

func WithCoverage(ctx context.Context, c *Coverage) context.Context {
	return context.WithValue(ctx, coverageKey{}, c)
}
func CoverageFrom(ctx context.Context) *Coverage {
	c, _ := ctx.Value(coverageKey{}).(*Coverage)
	return c
}
func Note(ctx context.Context, code, path string, incomplete bool) {
	if c := CoverageFrom(ctx); c != nil {
		c.Note(code, path, incomplete)
	}
}
func (c *Coverage) Note(code, path string, incomplete bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.DiagnosticCount++
	if incomplete {
		c.complete = false
		c.stats.Skipped++
	}
	if len(c.diagnostics) < 1024 {
		c.diagnostics = append(c.diagnostics, Diagnostic{code, SafeLocator(path), incomplete})
	}
}
func (c *Coverage) Processed(n int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Processed++
	c.stats.Bytes += int64(n)
}
func (c *Coverage) Snapshot() (bool, ScanStats, []Diagnostic) {
	if c == nil {
		return true, ScanStats{}, []Diagnostic{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	d := append([]Diagnostic{}, c.diagnostics...)
	return c.complete, c.stats, d
}

type Scope struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Policy string `json:"policy"`
}

func (c *Coverage) RegisterScope(kind, target string, policy any) {
	if c == nil {
		return
	}
	b, _ := json.Marshal(policy)
	c.mu.Lock()
	defer c.mu.Unlock()
	h := sha256.Sum256(b)
	digest := h[:]
	if len(c.policyKey) > 0 {
		mac := hmac.New(sha256.New, c.policyKey)
		_, _ = mac.Write(b)
		digest = mac.Sum(nil)
	}
	s := Scope{kind, SafeLocator(target), hex.EncodeToString(digest)}
	for _, x := range c.scopes {
		if x == s {
			return
		}
	}
	c.scopes = append(c.scopes, s)
}
func (c *Coverage) Filtered() {
	if c != nil {
		c.mu.Lock()
		c.filtered = true
		c.mu.Unlock()
	}
}
func (c *Coverage) RevealSecrets() {
	if c != nil {
		c.mu.Lock()
		c.secretsRevealed = true
		c.mu.Unlock()
	}
}

func (c *Coverage) SetIdentityScope(key []byte) {
	if c == nil || len(key) < 32 {
		return
	}
	h := sha256.Sum256(key)
	c.mu.Lock()
	c.identityScope = hex.EncodeToString(h[:8])
	c.policyKey = append([]byte(nil), key...)
	c.mu.Unlock()
}

type ScanResult struct {
	SecretsRevealed  bool         `json:"secrets_revealed"`
	IdentityScope    string       `json:"identity_scope,omitempty"`
	Scope            []Scope      `json:"scope"`
	Filtered         bool         `json:"filtered"`
	SchemaVersion    string       `json:"schema_version"`
	Complete         bool         `json:"complete"`
	CompletionReason string       `json:"completion_reason"`
	Count            int          `json:"count"`
	Findings         []Finding    `json:"findings"`
	Truncated        bool         `json:"truncated"`
	Stats            ScanStats    `json:"stats"`
	Diagnostics      []Diagnostic `json:"diagnostics"`
}

func NewResult(fs []Finding, c *Coverage) ScanResult {
	complete, stats, d := c.Snapshot()
	if fs == nil {
		fs = []Finding{}
	}
	truncated := false
	for _, f := range fs {
		if IsIncompleteFinding(f) {
			truncated = true
			complete = false
		}
	}
	reason := "completed"
	if !complete {
		reason = "incomplete"
	}
	var scopes []Scope
	filtered := false
	identityScope := ""
	revealed := false
	if c != nil {
		c.mu.Lock()
		scopes = append([]Scope{}, c.scopes...)
		filtered = c.filtered
		identityScope = c.identityScope
		revealed = c.secretsRevealed
		c.mu.Unlock()
	}
	sort.Slice(scopes, func(i, j int) bool {
		if scopes[i].Kind != scopes[j].Kind {
			return scopes[i].Kind < scopes[j].Kind
		}
		if scopes[i].Target != scopes[j].Target {
			return scopes[i].Target < scopes[j].Target
		}
		return scopes[i].Policy < scopes[j].Policy
	})
	sort.SliceStable(d, func(i, j int) bool {
		if d[i].Path != d[j].Path {
			return d[i].Path < d[j].Path
		}
		return d[i].Code < d[j].Code
	})
	return ScanResult{SecretsRevealed: revealed, SchemaVersion: "1.4", Complete: complete, CompletionReason: reason, Count: len(fs), Findings: fs, Truncated: truncated, Stats: stats, Diagnostics: d, Scope: scopes, Filtered: filtered, IdentityScope: identityScope}
}
