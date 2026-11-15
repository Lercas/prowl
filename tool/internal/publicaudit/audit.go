// Package publicaudit inspects public-key permissions without exercising write capabilities.
package publicaudit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

const Revision = "public-acl-v3-firebase"
const maxRequests = 32
const maxBody = 64 << 10

var appID = regexp.MustCompile(`^[A-Z0-9]{10}$`)
var apiKey = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

// Auditor belongs to one invocation. No endpoint override or discovered host is accepted.
type Auditor struct {
	client      *http.Client
	mu          sync.Mutex
	entries     map[[32]byte]*entry
	attempts    int
	slots       chan struct{}
	collections []string
}
type entry struct {
	done   chan struct{}
	result *model.PublicKeyAudit
}

func New(timeout time.Duration) *Auditor {
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	client := safehttp.Client(timeout)
	// Even same-host redirects could forward the key to an unrelated path.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Auditor{client: client, entries: make(map[[32]byte]*entry), slots: make(chan struct{}, 4)}
}

func Supports(typ string) bool { return typ == "algolia-api-key" || GoogleType(typ) }

func GoogleType(typ string) bool {
	switch typ {
	case "gcp_api_key", "gcp-api-key", "google-api-key", "google-gemini-api-key":
		return true
	}
	return false
}

func Inconclusive(reason string) *model.PublicKeyAudit {
	return &model.PublicKeyAudit{Provider: "algolia", Status: "inconclusive", Reason: reason}
}

// Audit accepts only explicit sibling scalar bindings from a safely parsed object.
// A denied request is inconclusive: it does not prove that a key is dead or safe.
func (a *Auditor) Audit(ctx context.Context, typ, key string, bindings map[string]string) *model.PublicKeyAudit {
	if !Supports(typ) {
		return nil
	}
	if typ != "algolia-api-key" {
		return a.auditFirebase(ctx, key, bindings)
	}
	app, ok := applicationID(bindings)
	if !ok || !apiKey.MatchString(key) {
		return Inconclusive("missing or ambiguous application binding")
	}
	hash := sha256.Sum256([]byte("algolia\x00" + app + "\x00" + key))
	return a.cached(ctx, hash, "algolia", func() *model.PublicKeyAudit { return a.probe(ctx, app, key) })
}

func (a *Auditor) cached(ctx context.Context, hash [32]byte, provider string, probe func() *model.PublicKeyAudit) *model.PublicKeyAudit {
	fail := func(reason string) *model.PublicKeyAudit {
		return &model.PublicKeyAudit{Provider: provider, Status: "inconclusive", Reason: reason}
	}
	if ctx.Err() != nil {
		return fail("audit canceled")
	}
	a.mu.Lock()
	if e := a.entries[hash]; e != nil {
		a.mu.Unlock()
		select {
		case <-ctx.Done():
			return fail("audit canceled")
		case <-e.done:
			return clone(e.result)
		}
	}
	if a.attempts >= maxRequests {
		a.mu.Unlock()
		return fail("audit request budget exhausted")
	}
	a.attempts++
	e := &entry{done: make(chan struct{})}
	a.entries[hash] = e
	a.mu.Unlock()
	var result *model.PublicKeyAudit
	select {
	case <-ctx.Done():
		result = fail("audit canceled")
	case a.slots <- struct{}{}:
		result = probe()
		<-a.slots
	}
	a.mu.Lock()
	e.result = result
	if result.Status == "inconclusive" {
		delete(a.entries, hash)
	}
	close(e.done)
	a.mu.Unlock()
	return clone(result)
}

func clone(r *model.PublicKeyAudit) *model.PublicKeyAudit {
	c := *r
	c.Capabilities = append([]string(nil), r.Capabilities...)
	c.Checks = append([]model.PublicAuditCheck(nil), r.Checks...)
	return &c
}

func applicationID(bindings map[string]string) (string, bool) {
	if len(bindings) > 128 {
		return "", false
	}
	found := ""
	normalize := strings.NewReplacer("_", "", "-", "", ".", "")
	for name, value := range bindings {
		switch normalize.Replace(strings.ToLower(name)) {
		case "algoliaappid", "algoliaapplicationid", "applicationid", "appid":
			if !appID.MatchString(value) || found != "" && found != value {
				return "", false
			}
			found = value
		}
	}
	return found, found != ""
}

func (a *Auditor) probe(ctx context.Context, app, key string) *model.PublicKeyAudit {
	// Validated scalars cannot alter the fixed HTTPS authority, path or headers.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+strings.ToLower(app)+".algolia.net/1/keys/"+key, nil)
	if err != nil {
		return Inconclusive("invalid audit request")
	}
	req.Header.Set("X-Algolia-API-Key", key)
	req.Header.Set("X-Algolia-Application-Id", app)
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req) // #nosec G704 -- fixed provider authority with validated application ID; safehttp guards resolved addresses.
	if err != nil {
		return Inconclusive("audit transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Inconclusive("provider did not disclose ACL")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return Inconclusive("invalid or oversized ACL response")
	}
	result := parseACL(body, key)
	result.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return result
}

// Keep response-controlled text out of all reports, including error messages.
func parseACL(body []byte, key string) *model.PublicKeyAudit {
	invalid := func() *model.PublicKeyAudit { return Inconclusive("invalid ACL response") }
	if jsonstrict.ValidateEncoding(body) != nil || !uniqueJSON(body) {
		return invalid()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return invalid()
	}
	// encoding/json's struct matching is case-insensitive; use exact provider fields.
	for name := range fields {
		if name != "acl" && strings.EqualFold(name, "acl") || name != "value" && strings.EqualFold(name, "value") {
			return invalid()
		}
	}
	var response struct {
		ACL   []string
		Value string
	}
	if json.Unmarshal(fields["acl"], &response.ACL) != nil || json.Unmarshal(fields["value"], &response.Value) != nil || response.Value != key || len(response.ACL) == 0 || len(response.ACL) > 32 {
		return invalid()
	}
	known := strings.Fields("search addObject analytics browse deleteObject deleteIndex editSettings inference listIndexes logs personalization recommendation seeUnretrievableAttributes settings usage nluWriteProject nluReadProject nluWriteEntity nluReadEntity nluWriteIntent nluReadIntent nluPrediction nluReadAnswers")
	allowed := make(map[string]bool, len(known))
	for _, permission := range known {
		allowed[permission] = true
	}
	seen := map[string]bool{}
	for _, permission := range response.ACL {
		if !allowed[permission] || seen[permission] {
			return invalid()
		}
		seen[permission] = true
	}
	sort.Strings(response.ACL)
	result := &model.PublicKeyAudit{Provider: "algolia", Status: "search_only", Capabilities: response.ACL,
		Reason: "ACL contains only search; other access restrictions were not assessed"}
	if len(response.ACL) != 1 || response.ACL[0] != "search" {
		result.Status = "excess_permissions"
		result.Reason = "ACL grants permissions beyond public search"
	}
	return result
}
