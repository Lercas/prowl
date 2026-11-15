package publicaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/model"
)

var googleKey = regexp.MustCompile(`^AIza[0-9A-Za-z_-]{35}$`)
var projectID = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
var databaseHost = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9](?:\.firebaseio\.com|\.[a-z][a-z0-9-]{0,39}\.firebasedatabase\.app)$`)
var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)

// NewWithCollections adds only explicitly selected Firestore collection paths.
// These are relative paths, not endpoint overrides or discovery guesses.
func NewWithCollections(timeout time.Duration, collections []string) (*Auditor, error) {
	canonical, err := ValidateCollections(collections)
	if err != nil {
		return nil, err
	}
	a := New(timeout)
	a.collections = canonical
	return a, nil
}

func ValidateCollections(paths []string) ([]string, error) {
	if len(paths) > 8 {
		return nil, errors.New("at most 8 Firestore collection paths may be audited")
	}
	seen := map[string]bool{}
	var out []string
	for _, path := range paths {
		if !utf8.ValidString(path) || len(path) == 0 || len(path) > 1024 || strings.ContainsAny(path, "%\\?#") {
			return nil, errors.New("invalid Firestore collection path")
		}
		parts := strings.Split(path, "/")
		if len(parts)%2 != 1 || len(parts) > 21 {
			return nil, errors.New("collection paths for Firestore must have an odd number of segments")
		}
		for _, part := range parts {
			if part == "" || part == "." || part == ".." || len(part) > 128 || strings.HasPrefix(part, "__") && strings.HasSuffix(part, "__") {
				return nil, errors.New("invalid Firestore collection segment")
			}
			for _, r := range part {
				if unicode.IsControl(r) {
					return nil, errors.New("invalid Firestore collection segment")
				}
			}
		}
		if !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (a *Auditor) Policy() map[string]any {
	scopes := make([]string, 0, len(a.collections))
	for _, path := range a.collections {
		scopes = append(scopes, scopeHash("firestore-collection", path))
	}
	tables := make([]string, 0, len(a.tables))
	for _, table := range a.tables {
		tables = append(tables, scopeHash("supabase-table", table))
	}
	return map[string]any{"bindings": "structured-static-js-android-google-services-and-firebase-xml", "rtdb": "configured root shallow GET", "storage": "configured bucket root list, one result", "firestore_collections": scopes, "firestore_mask": "prowlAuditMetadataOnly", "supabase_tables": tables, "supabase": "public schema HEAD limit=1, no count, public key only"}
}

type firebaseProbe struct{ service, url, project, collection, bucket string }

func firebaseFail(reason string) *model.PublicKeyAudit {
	return &model.PublicKeyAudit{Provider: "firebase", Status: "inconclusive", Reason: reason}
}

func normalizedBinding(name string) string {
	return strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(name))
}

func firebaseBinding(bindings map[string]string, names ...string) (value string, present, ok bool) {
	ok = true
	for name, raw := range bindings {
		for _, alias := range names {
			if normalizedBinding(name) != alias {
				continue
			}
			if raw == "" || present && value != raw {
				ok = false
			}
			value, present = raw, true
		}
	}
	return
}

func (a *Auditor) auditFirebase(ctx context.Context, key string, bindings map[string]string) *model.PublicKeyAudit {
	// The API key anchors the finding; it is never sent in an unauthenticated rules probe.
	if len(bindings) > 128 {
		return firebaseFail("invalid or ambiguous Firebase configuration")
	}
	db, dbPresent, dbOK := firebaseBinding(bindings, "databaseurl", "firebasedatabaseurl")
	bucket, bucketPresent, bucketOK := firebaseBinding(bindings, "storagebucket", "firebasestoragebucket")
	project, projectPresent, projectOK := firebaseBinding(bindings, "projectid", "firebaseprojectid")
	_, authPresent, _ := firebaseBinding(bindings, "authdomain", "firebaseauthdomain")
	_, schemaPresent, _ := firebaseBinding(bindings, "firebaseconfig")
	if !dbPresent && !bucketPresent && !authPresent && !schemaPresent && !(projectPresent && len(a.collections) > 0) {
		return nil
	}
	if len(bindings) > 128 || !googleKey.MatchString(key) || !dbOK || !bucketOK || !projectOK {
		return firebaseFail("invalid or ambiguous Firebase configuration")
	}
	if projectPresent && !projectID.MatchString(project) || !projectPresent && len(a.collections) > 0 {
		return firebaseFail("missing or invalid Firebase project binding")
	}
	var probes []firebaseProbe
	if dbPresent {
		u, err := url.Parse(db)
		if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" || !databaseHost.MatchString(u.Host) {
			return firebaseFail("invalid Firebase database binding")
		}
		probes = append(probes, firebaseProbe{service: "rtdb", url: "https://" + u.Host + "/.json?shallow=true", project: project})
	}
	if bucketPresent {
		var valid bool
		bucket, valid = canonicalBucket(bucket)
		if !valid {
			return firebaseFail("invalid Firebase bucket binding")
		}
		probes = append(probes, firebaseProbe{service: "storage", url: "https://firebasestorage.googleapis.com/v0/b/" + bucket + "/o?maxResults=1", project: project, bucket: bucket})
	}
	for _, collection := range a.collections {
		parts := strings.Split(collection, "/")
		for i := range parts {
			parts[i] = url.PathEscape(parts[i])
		}
		q := url.Values{"pageSize": {"1"}, "mask.fieldPaths": {"prowlAuditMetadataOnly"}}
		endpoint := "https://firestore.googleapis.com/v1/projects/" + project + "/databases/(default)/documents/" + strings.Join(parts, "/") + "?" + q.Encode()
		if strings.Contains(endpoint, key) {
			return firebaseFail("Firebase target would contain the key value")
		}
		probes = append(probes, firebaseProbe{service: "firestore", url: endpoint, project: project, collection: collection})
	}
	if len(probes) == 0 {
		return firebaseFail("no configured Firebase read target; Firestore needs an explicit collection")
	}
	result := &model.PublicKeyAudit{Provider: "firebase", Status: "read_denied", Reason: "Unauthenticated reads denied at requested targets; other paths and operations were not assessed"}
	incomplete, allowed := false, false
	var latest time.Time
	for _, probe := range probes {
		hash := sha256.Sum256([]byte("firebase\x00" + probe.service + "\x00" + probe.url))
		observed := a.cached(ctx, hash, "firebase", func() *model.PublicKeyAudit { return a.firebaseRead(ctx, probe) })
		if len(observed.Checks) == 0 {
			observed.Checks = []model.PublicAuditCheck{{Service: probe.service, Scope: scopeHash(probe.service, probe.url), Status: "inconclusive", Reason: observed.Reason}}
		}
		result.Checks = append(result.Checks, observed.Checks...)
		if checked, err := time.Parse(time.RFC3339Nano, observed.CheckedAt); err == nil && checked.After(latest) {
			latest = checked
			result.CheckedAt = observed.CheckedAt
		}
		if observed.Status == "inconclusive" {
			incomplete = true
		}
		if observed.Status == "public_read_allowed" {
			allowed = true
			result.Capabilities = append(result.Capabilities, "firebase_"+probe.service+"_public_read")
		}
	}
	sort.Strings(result.Capabilities)
	result.Capabilities = compactStrings(result.Capabilities)
	if allowed {
		result.Status = "public_read_allowed"
		result.Reason = "An unauthenticated read was accepted; intended data visibility and other rules were not assessed"
	}
	if incomplete {
		result.Status = "inconclusive"
		result.Reason = "Some Firebase read checks were inconclusive; inspect individual checks for observed access"
	}
	return result
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func scopeHash(service, endpoint string) string {
	hash := sha256.Sum256([]byte(service + "\x00" + endpoint))
	return hex.EncodeToString(hash[:])
}

func (a *Auditor) firebaseRead(ctx context.Context, probe firebaseProbe) *model.PublicKeyAudit {
	check := model.PublicAuditCheck{Service: probe.service, Scope: scopeHash(probe.service, probe.url), Status: "inconclusive"}
	result := firebaseFail("Firebase read was inconclusive")
	defer func() {
		check.CheckedAt = result.CheckedAt
		check.Status = result.Status
		check.Reason = result.Reason
		result.Checks = []model.PublicAuditCheck{check}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.url, nil)
	if err != nil {
		result.Reason = "invalid Firebase read request"
		return result
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req) // #nosec G704 -- validated Firebase HTTPS authority; safehttp guards DNS/IP and all redirects are refused.
	if err != nil {
		result.Reason = "audit transport failed"
		return result
	}
	defer resp.Body.Close()
	result.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(raw) > maxBody || !strictFirebaseJSON(raw) {
		result.Reason = "invalid or oversized Firebase response"
		return result
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		if !firebaseDenial(raw, resp.StatusCode, probe.service) {
			result.Reason = "unrecognized Firebase denial response"
			return result
		}
		result.Status = "read_denied"
		result.Reason = "Unauthenticated read denied at this target; other paths and operations were not assessed"
		return result
	}
	if resp.StatusCode != http.StatusOK {
		result.Reason = "Firebase did not provide a conclusive read response"
		return result
	}
	present, valid := firebaseData(raw, probe)
	if !valid {
		result.Reason = "unexpected Firebase read response"
		return result
	}
	check.DataState = "empty"
	if present {
		check.DataState = "present"
	}
	result.Status = "public_read_allowed"
	result.Reason = "Unauthenticated read accepted at this target; intended visibility was not assessed"
	return result
}

func strictFirebaseJSON(raw []byte) bool {
	if jsonstrict.ValidateEncoding(raw) != nil {
		return false
	}
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "{") {
		return uniqueJSON(raw)
	}
	// RTDB shallow can return primitives; wrapping applies the same duplicate/depth/token budget to any shape.
	return uniqueJSON(append(append([]byte(`{"value":`), raw...), '}'))
}

func firebaseDenial(raw []byte, status int, service string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	if service == "rtdb" {
		var message string
		return json.Unmarshal(fields["error"], &message) == nil && message == "Permission denied"
	}
	var detail map[string]json.RawMessage
	if json.Unmarshal(fields["error"], &detail) != nil {
		return false
	}
	var code int
	var label string
	if json.Unmarshal(detail["code"], &code) != nil || code != status {
		return false
	}
	if service == "storage" {
		var message string
		return json.Unmarshal(detail["message"], &message) == nil && message != ""
	}
	return json.Unmarshal(detail["status"], &label) == nil && (label == "PERMISSION_DENIED" || label == "UNAUTHENTICATED")
}

func firebaseData(raw []byte, probe firebaseProbe) (bool, bool) {
	if probe.service == "rtdb" {
		trimmed := strings.TrimSpace(string(raw))
		if trimmed == "null" {
			return false, true
		}
		if strings.HasPrefix(trimmed, "{") {
			var object map[string]json.RawMessage
			if json.Unmarshal(raw, &object) != nil {
				return false, false
			}
			for _, value := range object {
				if strings.TrimSpace(string(value)) != "true" {
					return false, false
				}
			}
			return len(object) > 0, true
		}
		if strings.HasPrefix(trimmed, "[") {
			return false, false
		}
		return true, true // Strict JSON validation already established a primitive.
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return false, false
	}
	allowed := map[string]bool{"nextPageToken": true}
	if probe.service == "storage" {
		allowed["items"], allowed["prefixes"] = true, true
	} else {
		allowed["documents"] = true
	}
	for name := range object {
		if !allowed[name] {
			return false, false
		}
	}
	if next, ok := object["nextPageToken"]; ok {
		var token string
		if strings.TrimSpace(string(next)) == "null" || json.Unmarshal(next, &token) != nil {
			return false, false
		}
	}
	if probe.service == "storage" {
		var items []map[string]json.RawMessage
		var prefixes []string
		if item, ok := object["items"]; ok && (strings.TrimSpace(string(item)) == "null" || json.Unmarshal(item, &items) != nil) {
			return false, false
		}
		if prefix, ok := object["prefixes"]; ok && (strings.TrimSpace(string(prefix)) == "null" || json.Unmarshal(prefix, &prefixes) != nil) {
			return false, false
		}
		if len(items)+len(prefixes) > 1 {
			return false, false
		}
		for _, item := range items {
			if !canonicalResponseMembers(item, "name", "bucket") {
				return false, false
			}
			var name, bucket string
			if json.Unmarshal(item["name"], &name) != nil || name == "" {
				return false, false
			}
			if b, ok := item["bucket"]; ok && (json.Unmarshal(b, &bucket) != nil || bucket != probe.bucket) {
				return false, false
			}
		}
		for _, prefix := range prefixes {
			if prefix == "" {
				return false, false
			}
		}
		return len(items)+len(prefixes) > 0, true
	}
	var documents []map[string]json.RawMessage
	if data, ok := object["documents"]; ok && (strings.TrimSpace(string(data)) == "null" || json.Unmarshal(data, &documents) != nil) {
		return false, false
	}
	if len(documents) > 1 {
		return false, false
	}
	prefix := "projects/" + probe.project + "/databases/(default)/documents/" + probe.collection + "/"
	for _, document := range documents {
		if !canonicalResponseMembers(document, "name", "fields") {
			return false, false
		}
		var name string
		if json.Unmarshal(document["name"], &name) != nil || !strings.HasPrefix(name, prefix) || strings.TrimPrefix(name, prefix) == "" || strings.Contains(strings.TrimPrefix(name, prefix), "/") {
			return false, false
		}
		if data, ok := document["fields"]; ok {
			var fields map[string]json.RawMessage
			if strings.TrimSpace(string(data)) == "null" || json.Unmarshal(data, &fields) != nil || len(fields) > 1 {
				return false, false
			}
			for name := range fields {
				if name != "prowlAuditMetadataOnly" {
					return false, false
				}
			}
		}
	}
	return len(documents) > 0, true
}

func canonicalResponseMembers(fields map[string]json.RawMessage, names ...string) bool {
	for name := range fields {
		for _, canonical := range names {
			if name != canonical && strings.EqualFold(name, canonical) {
				return false
			}
		}
	}
	return true
}

func canonicalBucket(raw string) (string, bool) {
	bucket := raw
	if strings.HasPrefix(raw, "gs://") {
		u, err := url.Parse(raw)
		if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" {
			return "", false
		}
		bucket = u.Host
	}
	if !bucketName.MatchString(bucket) || net.ParseIP(bucket) != nil {
		return "", false
	}
	parts := strings.Split(bucket, ".")
	if len(parts) == 1 && len(bucket) > 63 {
		return "", false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return "", false
		}
	}
	return bucket, true
}
