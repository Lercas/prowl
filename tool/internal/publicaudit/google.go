package publicaudit

import (
	"bytes"
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

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/model"
)

var googleResource = regexp.MustCompile(`^projects/[1-9][0-9]{0,19}/locations/global/keys/[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var googleOAuthToken = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)
var googleService = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,251}\.[a-zA-Z]{2,20}$`)
var googleMethod = regexp.MustCompile(`^[A-Za-z0-9_.]+\*?$`)
var googlePackage = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)
var googleBundle = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$`)

// NewWithGoogleRestrictions snapshots operator credentials before sharing the auditor.
// Neither the credential nor a mechanism for replacing it is exposed by the instance.
func NewWithGoogleRestrictions(timeout time.Duration, collections, tables []string, token string) (*Auditor, error) {
	auditor, err := NewWithTargets(timeout, collections, tables)
	if err != nil {
		return nil, err
	}
	if err = auditor.configureGoogleRestrictions(token); err != nil {
		return nil, err
	}
	return auditor, nil
}

func (a *Auditor) configureGoogleRestrictions(token string) error {
	if len(token) == 0 || len(token) > 8192 || !googleOAuthToken.MatchString(token) {
		return errors.New("a valid PROWL_GOOGLE_AUDIT_TOKEN is required for --audit-google-restrictions")
	}
	a.googleAuthorize = func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
	return nil
}

func googleFail(reason, scope string) *model.PublicKeyAudit {
	return &model.PublicKeyAudit{Provider: "google", Status: "inconclusive", Reason: reason, Checks: []model.PublicAuditCheck{{Service: "google_api_restrictions", Scope: scopeHash("google_api_restrictions", scope), Status: "inconclusive", Reason: reason}}}
}

func (a *Auditor) auditGoogleRestrictions(ctx context.Context, key string) *model.PublicKeyAudit {
	if !googleKey.MatchString(key) {
		return googleFail("unsupported Google key shape", "")
	}
	hash := sha256.Sum256([]byte("google-key-metadata-v1\x00" + key))
	result := a.cached(ctx, hash, "google", func() *model.PublicKeyAudit {
		fail := func(reason string) *model.PublicKeyAudit { return googleFail(reason, key) }
		lookup, ok := a.googleMetadata(ctx, "keys:lookupKey?keyString="+url.QueryEscape(key))
		if !ok {
			return fail("Google did not disclose key ownership metadata")
		}
		fields, ok := googleObject(lookup, "parent", "name")
		if !ok {
			return fail("invalid Google key ownership metadata")
		}
		name, nameOK := googleString(fields["name"])
		parent, parentOK := googleString(fields["parent"])
		if !nameOK || !parentOK || !googleResource.MatchString(name) || parent != strings.Split(name, "/keys/")[0] {
			return fail("invalid Google key resource binding")
		}
		// cached reserves the lookup request. Reserve the second GET against the same global budget.
		a.mu.Lock()
		allowed := a.attempts < maxRequests
		if allowed {
			a.attempts++
		}
		a.mu.Unlock()
		if !allowed {
			return fail("audit request budget exhausted")
		}
		body, ok := a.googleMetadata(ctx, name)
		if !ok {
			return fail("Google did not disclose key restriction metadata")
		}
		return parseGoogleRestrictions(body, name)
	})
	if len(result.Checks) == 0 {
		return googleFail(result.Reason, key)
	}
	return result
}

func (a *Auditor) googleMetadata(ctx context.Context, resource string) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://apikeys.googleapis.com/v2/"+resource, nil)
	if err != nil {
		return nil, false
	}
	a.googleAuthorize(req)
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req) // #nosec G704 -- fixed Google authority, validated resource or escaped key; safehttp pins public addresses.
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	return body, err == nil && len(body) <= maxBody && jsonstrict.ValidateEncoding(body) == nil && uniqueJSON(body)
}

func googleObject(raw []byte, names ...string) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, false
	}
	for name := range fields {
		known := false
		for _, allowed := range names {
			known = known || name == allowed
		}
		if !known {
			return nil, false
		}
	}
	return fields, true
}
func googleString(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	var value string
	if len(raw) < 2 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func googleStrings(raw json.RawMessage, max int) ([]string, bool) {
	var values []string
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" || json.Unmarshal(raw, &values) != nil || len(values) == 0 || len(values) > max {
		return nil, false
	}
	for _, v := range values {
		if len(v) == 0 || len(v) > 1024 || strings.ContainsAny(v, "\r\n\x00") {
			return nil, false
		}
	}
	return values, true
}

func parseGoogleRestrictions(body []byte, name string) *model.PublicKeyAudit {
	fail := func() *model.PublicKeyAudit {
		return googleFail("invalid or unsupported Google restriction metadata", name)
	}
	if jsonstrict.ValidateEncoding(body) != nil || !uniqueJSON(body) {
		return fail()
	}
	fields, ok := googleObject(body, "name", "uid", "displayName", "createTime", "updateTime", "deleteTime", "annotations", "restrictions", "etag", "serviceAccountEmail")
	actual, nameOK := googleString(fields["name"])
	if !ok || !nameOK || actual != name {
		return fail()
	}
	for _, field := range []string{"deleteTime", "serviceAccountEmail"} {
		if raw, present := fields[field]; present {
			v, ok := googleString(raw)
			if !ok || v != "" {
				return fail()
			}
		}
	}
	restrictions := map[string]json.RawMessage{}
	if raw, present := fields["restrictions"]; present {
		restrictions, ok = googleObject(raw, "apiTargets", "browserKeyRestrictions", "serverKeyRestrictions", "androidKeyRestrictions", "iosKeyRestrictions")
		if !ok {
			return fail()
		}
	}
	apiConfigured := false
	if raw, present := restrictions["apiTargets"]; present {
		var targets []json.RawMessage
		if string(bytes.TrimSpace(raw)) == "null" || json.Unmarshal(raw, &targets) != nil || len(targets) > 128 {
			return fail()
		}
		for _, raw := range targets {
			target, ok := googleObject(raw, "service", "methods")
			service, valid := googleString(target["service"])
			if !ok || !valid || !googleService.MatchString(service) {
				return fail()
			}
			if methods, present := target["methods"]; present {
				var list []string
				if string(bytes.TrimSpace(methods)) == "null" || json.Unmarshal(methods, &list) != nil || len(list) > 128 {
					return fail()
				}
				for _, method := range list {
					if len(method) > 256 || !googleMethod.MatchString(method) {
						return fail()
					}
				}
			}
		}
		apiConfigured = len(targets) > 0
	}
	clientConfigured := false
	for _, kind := range []string{"browserKeyRestrictions", "serverKeyRestrictions", "androidKeyRestrictions", "iosKeyRestrictions"} {
		raw, present := restrictions[kind]
		if !present {
			continue
		}
		if clientConfigured || !validGoogleClientRestriction(kind, raw) {
			return fail()
		}
		clientConfigured = true
	}
	result := &model.PublicKeyAudit{Provider: "google", Status: "restrictions_configured", CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), Reason: "Client and API restriction fields are configured; policy strength and effective access were not tested"}
	for _, dimension := range []struct {
		name       string
		configured bool
	}{{"client", clientConfigured}, {"api", apiConfigured}} {
		check := model.PublicAuditCheck{Service: "google_" + dimension.name + "_restrictions", Scope: scopeHash("google_"+dimension.name+"_restrictions", name), Status: "restrictions_configured", CheckedAt: result.CheckedAt, Reason: "Restriction fields are configured; effective access was not tested"}
		if !dimension.configured {
			check.Status = "unrestricted"
			check.Reason = "No " + dimension.name + " restriction fields are configured"
			result.Status = "unrestricted"
			result.Capabilities = append(result.Capabilities, "google_"+dimension.name+"_unrestricted")
			result.Reason = "At least one restriction dimension is unconfigured; provider access and exploitability were not tested"
		}
		result.Checks = append(result.Checks, check)
	}
	return result
}

func validGoogleClientRestriction(kind string, raw json.RawMessage) bool {
	field := map[string]string{"browserKeyRestrictions": "allowedReferrers", "serverKeyRestrictions": "allowedIps", "androidKeyRestrictions": "allowedApplications", "iosKeyRestrictions": "allowedBundleIds"}[kind]
	object, ok := googleObject(raw, field)
	if !ok {
		return false
	}
	if kind == "androidKeyRestrictions" {
		var apps []json.RawMessage
		if json.Unmarshal(object[field], &apps) != nil || len(apps) == 0 || len(apps) > 128 {
			return false
		}
		for _, raw := range apps {
			app, ok := googleObject(raw, "sha1Fingerprint", "packageName")
			fingerprint, valid := googleString(app["sha1Fingerprint"])
			name, nameOK := googleString(app["packageName"])
			decoded, err := hex.DecodeString(strings.ReplaceAll(fingerprint, ":", ""))
			if !ok || !valid || !nameOK || !googlePackage.MatchString(name) || len(decoded) != 20 || err != nil {
				return false
			}
		}
		return true
	}
	values, ok := googleStrings(object[field], 128)
	if !ok {
		return false
	}
	for _, value := range values {
		if kind == "serverKeyRestrictions" {
			if net.ParseIP(value) == nil {
				if _, _, err := net.ParseCIDR(value); err != nil {
					return false
				}
			}
		}
		if kind == "iosKeyRestrictions" && !googleBundle.MatchString(value) {
			return false
		}
	}
	return true
}

func mergeGoogleAudit(google, firebase *model.PublicKeyAudit) *model.PublicKeyAudit {
	if firebase == nil {
		return google
	}
	result := clone(firebase)
	result.Provider = "google"
	result.Checks = append(result.Checks, google.Checks...)
	result.Capabilities = append(result.Capabilities, google.Capabilities...)
	sort.Strings(result.Capabilities)
	result.Capabilities = compactStrings(result.Capabilities)
	observed, err := time.Parse(time.RFC3339Nano, google.CheckedAt)
	previous, previousErr := time.Parse(time.RFC3339Nano, result.CheckedAt)
	if err == nil && (previousErr != nil || observed.After(previous)) {
		result.CheckedAt = google.CheckedAt
	}
	result.Reason = "Google key restriction metadata and Firebase read observations are separate checks; intended access and effective policy strength were not assessed"
	if google.Status == "unrestricted" {
		result.Status = "unrestricted"
	}
	if google.Status == "inconclusive" || firebase.Status == "inconclusive" {
		result.Status = "inconclusive"
	}
	return result
}
