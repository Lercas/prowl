package publicaudit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
)

var supabaseRef = regexp.MustCompile(`^[a-z0-9]{20}$`)
var publishableKey = regexp.MustCompile(`^sb_publishable_[A-Za-z0-9_-]{20,128}$`)
var supabaseTable = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// NewWithTargets adds operator-selected paths without discovering database objects.
func NewWithTargets(timeout time.Duration, collections, tables []string) (*Auditor, error) {
	a, err := NewWithCollections(timeout, collections)
	if err != nil {
		return nil, err
	}
	a.tables, err = ValidateTables(tables)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func ValidateTables(tables []string) ([]string, error) {
	if len(tables) > 8 {
		return nil, errors.New("at most 8 Supabase table names may be audited")
	}
	seen := map[string]bool{}
	var out []string
	for _, table := range tables {
		if !supabaseTable.MatchString(table) {
			return nil, errors.New("invalid Supabase table name; use a simple public-schema identifier")
		}
		if !seen[table] {
			seen[table] = true
			out = append(out, table)
		}
	}
	sort.Strings(out)
	return out, nil
}

// supabasePublicKey classifies claims only; it does not authenticate a JWT.
// Elevated keys and user sessions must never be exercised by this audit.
func supabasePublicKey(key string) (ref string, ok bool) {
	if publishableKey.MatchString(key) {
		return "", true
	}
	if len(key) > 8192 {
		return "", false
	}
	parts := strings.Split(key, ".")
	if len(parts) != 3 {
		return "", false
	}
	var decoded [3][]byte
	for i, part := range parts {
		b, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || base64.RawURLEncoding.EncodeToString(b) != part {
			return "", false
		}
		decoded[i] = b
	}
	if len(decoded[2]) != 32 || !strictFirebaseJSON(decoded[0]) || !strictFirebaseJSON(decoded[1]) {
		return "", false
	}
	var header map[string]json.RawMessage
	var claims map[string]json.RawMessage
	if json.Unmarshal(decoded[0], &header) != nil || json.Unmarshal(decoded[1], &claims) != nil || len(header) != 2 || len(claims) != 5 {
		return "", false
	}
	text := func(object map[string]json.RawMessage, name string) string {
		var value string
		_ = json.Unmarshal(object[name], &value)
		return value
	}
	if text(header, "alg") != "HS256" || text(header, "typ") != "JWT" || text(claims, "iss") != "supabase" || text(claims, "role") != "anon" {
		return "", false
	}
	for _, name := range []string{"iat", "exp"} {
		var value int64
		if json.Unmarshal(claims[name], &value) != nil || value <= 0 {
			return "", false
		}
	}
	ref = text(claims, "ref")
	return ref, supabaseRef.MatchString(ref)
}

func supabaseFail(reason string) *model.PublicKeyAudit {
	return &model.PublicKeyAudit{Provider: "supabase", Status: "inconclusive", Reason: reason}
}

func (a *Auditor) auditSupabase(ctx context.Context, key string, bindings map[string]string) *model.PublicKeyAudit {
	ref, ok := supabasePublicKey(key)
	if !ok {
		return nil
	}
	if len(bindings) > 128 {
		return supabaseFail("invalid or ambiguous Supabase configuration")
	}
	raw, present, valid := firebaseBinding(bindings, "supabaseurl", "supabaseprojecturl", "nextpublicsupabaseurl", "vitesupabaseurl", "reactappsupabaseurl", "expopublicsupabaseurl")
	if !present || !valid {
		return supabaseFail("missing or ambiguous Supabase project URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" || !strings.HasSuffix(u.Host, ".supabase.co") {
		return supabaseFail("invalid Supabase project URL")
	}
	project := strings.TrimSuffix(u.Host, ".supabase.co")
	if !supabaseRef.MatchString(project) || ref != "" && ref != project {
		return supabaseFail("invalid or mismatched Supabase project binding")
	}
	if len(a.tables) == 0 {
		return supabaseFail("Supabase audit requires explicit table names")
	}
	result := &model.PublicKeyAudit{Provider: "supabase", Status: "read_denied", Reason: "Selected table reads rejected; RLS configuration and other operations were not assessed"}
	allowed, incomplete := false, false
	var latest time.Time
	for _, table := range a.tables {
		endpoint := "https://" + project + ".supabase.co/rest/v1/" + table + "?limit=1"
		hash := sha256.Sum256([]byte("supabase\x00" + key + "\x00" + endpoint))
		observed := a.cached(ctx, hash, "supabase", func() *model.PublicKeyAudit { return a.supabaseRead(ctx, endpoint, key) })
		if len(observed.Checks) == 0 {
			observed.Checks = []model.PublicAuditCheck{{Service: "supabase-table", Scope: scopeHash("supabase-table", endpoint), Status: "inconclusive", Reason: observed.Reason}}
		}
		result.Checks = append(result.Checks, observed.Checks...)
		if checked, err := time.Parse(time.RFC3339Nano, observed.CheckedAt); err == nil && checked.After(latest) {
			latest = checked
			result.CheckedAt = observed.CheckedAt
		}
		allowed = allowed || observed.Status == "public_read_allowed"
		incomplete = incomplete || observed.Status == "inconclusive"
	}
	if allowed {
		result.Status = "public_read_allowed"
		result.Reason = "A selected read was accepted with a public application key and no user session; this does not prove RLS is disabled"
		result.Capabilities = []string{"public_schema_head_read"}
	}
	if incomplete {
		result.Status = "inconclusive"
		result.Reason = "One or more selected reads are inconclusive; retain individual observations and do not infer RLS configuration"
	}
	return result
}

func (a *Auditor) supabaseRead(ctx context.Context, endpoint, key string) *model.PublicKeyAudit {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return supabaseFail("invalid Supabase audit request")
	}
	req.Header.Set("apikey", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Profile", "public")
	resp, err := a.client.Do(req) // #nosec G704 -- fixed managed Supabase root with validated project/table; safehttp guards resolved addresses.
	if err != nil {
		return supabaseFail("Supabase audit transport failed")
	}
	defer resp.Body.Close()
	result := supabaseHeadResult(resp)
	result.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	result.Checks = []model.PublicAuditCheck{{CheckedAt: result.CheckedAt, Service: "supabase-table", Scope: scopeHash("supabase-table", endpoint), Status: result.Status, DataState: "", Reason: result.Reason}}
	return result
}

func supabaseHeadResult(resp *http.Response) *model.PublicKeyAudit {
	if resp.StatusCode == http.StatusForbidden {
		return &model.PublicKeyAudit{Provider: "supabase", Status: "read_denied", Reason: "Selected HEAD request rejected with HTTP 403; this does not establish RLS configuration"}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return supabaseFail("Supabase did not provide a recognized table read response")
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(resp.Header.Values("Content-Range")) != 1 {
		return supabaseFail("invalid Supabase table response headers")
	}
	// No count is requested. Keep even row counts and response headers out of reports.
	switch resp.Header.Get("Content-Range") {
	case "0-0/*", "*/*":
		return &model.PublicKeyAudit{Provider: "supabase", Status: "public_read_allowed", Reason: "Selected HEAD request accepted without a user session; empty results do not establish RLS configuration"}
	default:
		return supabaseFail("invalid Supabase bounded read range")
	}
}
