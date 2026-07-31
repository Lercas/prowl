// Package hermesaudit performs a bounded, authorized audit of Hermes Agent
// dashboards and exact-IP passive lookups. It never requests an environment
// value, session data, or provider credential from the target. When the public
// SPA shell exposes Hermes' own session-token marker, it may use that marker
// only for masked metadata responses (names, provider/source, and presence
// booleans); value/preview fields are ignored.
package hermesaudit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const (
	DefaultPort          = 9119
	defaultTimeout       = 12 * time.Second
	defaultRetries       = 2
	maxStatusBody        = 256 << 10
	maxAssetBody         = 1 << 20
	maxStaticAssets      = 12
	maxPublicFindings    = 50
	maxConfiguredSecrets = 128
	maxProviderBody      = 2 << 20
	maxRetryDelay        = 30 * time.Second
	defaultUserAgent     = "prowl-hermes-audit/0.1 (authorized asset audit)"
	providerUserAgent    = "prowl-hermes-audit/0.1 (authorized passive inventory)"
)

// Options controls the audit. Provider URLs are overrideable for tests and
// private mirrors, but production defaults always point at the official APIs.
type Options struct {
	HTTPClient     *http.Client
	Timeout        time.Duration
	MaxRetries     int
	ProviderURLs   map[string]string
	Providers      []string
	IncludePassive bool
	IncludeActive  bool
	Concurrency    int
	Authorized     bool
}

// ActiveResult contains only non-sensitive status metadata. Body is never
// retained or serialized.
type ActiveResult struct {
	Target                      string             `json:"target"`
	URL                         string             `json:"url,omitempty"`
	RootURL                     string             `json:"root_url,omitempty"`
	Reachable                   bool               `json:"reachable"`
	HTTPStatus                  int                `json:"http_status,omitempty"`
	RootStatus                  int                `json:"root_status,omitempty"`
	SchemaStatus                int                `json:"schema_status,omitempty"`
	AuthRequired                *bool              `json:"auth_required,omitempty"`
	ControlPlaneUnauthenticated bool               `json:"control_plane_unauthenticated"`
	Version                     string             `json:"version,omitempty"`
	AuthProviders               []string           `json:"auth_providers,omitempty"`
	HermesCandidate             bool               `json:"hermes_candidate"`
	RootHermesEvidence          bool               `json:"root_hermes_evidence,omitempty"`
	StaticAssetsChecked         int                `json:"static_assets_checked,omitempty"`
	SessionTokenExposed         bool               `json:"session_token_exposed,omitempty"`
	EnvStatus                   int                `json:"env_status,omitempty"`
	CredentialPoolStatus        int                `json:"credential_pool_status,omitempty"`
	CustomEndpointsStatus       int                `json:"custom_endpoints_status,omitempty"`
	ConfiguredSecrets           []ConfiguredSecret `json:"configured_secrets,omitempty"`
	PublicFindings              []PublicFinding    `json:"public_findings,omitempty"`
	Risk                        string             `json:"risk"`
	Error                       string             `json:"error,omitempty"`
	ObservedAt                  time.Time          `json:"observed_at"`
}

// PublicFinding is the intentionally small, redacted shape emitted when a
// dashboard shell or same-origin static asset contains a secret-looking value.
// The raw value and surrounding source are never retained in the report.
type PublicFinding struct {
	Type        string  `json:"type"`
	Confidence  float64 `json:"confidence"`
	Severity    string  `json:"severity"`
	Path        string  `json:"path"`
	Line        int     `json:"line"`
	Col         int     `json:"col"`
	Redacted    string  `json:"redacted"`
	Fingerprint string  `json:"fingerprint,omitempty"`
}

// ConfiguredSecret reports only name/presence metadata returned by Hermes'
// masked environment, credential-pool, or custom-endpoint views. The value
// and preview fields are deliberately absent.
type ConfiguredSecret struct {
	Name     string `json:"name"`
	Present  bool   `json:"present"`
	Surface  string `json:"surface,omitempty"`
	Provider string `json:"provider,omitempty"`
	Source   string `json:"source,omitempty"`
}

// PassiveResult contains a redacted summary of one exact-IP provider lookup.
// Provider payloads and banners are intentionally not included.
type PassiveResult struct {
	Provider       string    `json:"provider"`
	Target         string    `json:"target"`
	Status         string    `json:"status"` // found|not_found|rate_limited|unauthorized|error|disabled
	HTTPStatus     int       `json:"http_status,omitempty"`
	RetryAfter     string    `json:"retry_after,omitempty"`
	HermesEvidence bool      `json:"hermes_evidence"`
	Ports          []int     `json:"ports,omitempty"`
	Endpoint       string    `json:"endpoint,omitempty"`
	Error          string    `json:"error,omitempty"`
	ObservedAt     time.Time `json:"observed_at"`
}

// Report is the complete per-target output. It contains no secret-bearing
// response body and is safe to archive in ordinary asset-inventory storage.
type Report struct {
	Target  string          `json:"target"`
	Active  *ActiveResult   `json:"active,omitempty"`
	Passive []PassiveResult `json:"passive,omitempty"`
}

// Audit validates authorization and audits all targets with bounded
// concurrency. Targets must be literal IPs, optionally followed by a port.
func Audit(ctx context.Context, targets []string, opts Options) ([]Report, error) {
	if !opts.Authorized {
		return nil, errors.New("hermesaudit: refusing to run without explicit authorization")
	}
	if !opts.IncludeActive && !opts.IncludePassive {
		return nil, errors.New("hermesaudit: at least one of active or passive audit must be enabled")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.MaxRetries < 0 || opts.MaxRetries > 5 {
		return nil, errors.New("hermesaudit: max retries must be between 0 and 5")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 2
	}
	if opts.Concurrency > 8 {
		opts.Concurrency = 8
	}
	client := opts.HTTPClient
	if client == nil {
		client = safehttp.Client(opts.Timeout)
	}

	clean := dedupTargets(targets)
	if len(clean) == 0 {
		return nil, errors.New("hermesaudit: no IP targets supplied")
	}
	for _, target := range clean {
		if _, _, err := parseTarget(target); err != nil {
			return nil, fmt.Errorf("hermesaudit: invalid target %q: %w", target, err)
		}
	}

	providers := newProviders(client, opts)
	results := make([]Report, len(clean))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency && i < len(clean); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				target := clean[idx]
				report := Report{Target: target}
				if opts.IncludeActive {
					active := Probe(ctx, target, client)
					report.Active = &active
				}
				if opts.IncludePassive {
					for _, provider := range providers {
						if ctx.Err() != nil {
							return
						}
						report.Passive = append(report.Passive, provider.Lookup(ctx, target, opts.MaxRetries))
					}
				}
				results[idx] = report
			}
		}()
	}
	for i := range clean {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

// Probe performs bounded, credential-free GETs against an exact IP. For an
// IP without an explicit port it checks standard HTTPS/HTTP first and then the
// Hermes default port. If /api/status is absent, it falls back to the public
// dashboard root and same-origin static assets. It never sends cookies, bearer
// tokens, or query credentials to the target.
func Probe(ctx context.Context, target string, client *http.Client) ActiveResult {
	host, port, err := parseTarget(target)
	result := ActiveResult{Target: target, Risk: "unknown", ObservedAt: time.Now().UTC()}
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if client == nil {
		client = safehttp.Client(defaultTimeout)
	}

	for _, endpoint := range probeEndpoints(target, host, port) {
		base := endpoint.base()
		statusURL := base + "/api/status"
		status, body, reqErr := getBounded(ctx, client, statusURL, maxStatusBody)
		if reqErr != nil {
			continue
		}
		result.URL = statusURL
		result.HTTPStatus = status
		if status < 200 || status >= 300 {
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				result.Risk = "auth_gate_present"
				result.Reachable = true
				return result
			}
			continue
		}
		result.Reachable = true
		var payload map[string]any
		if json.Unmarshal(body, &payload) == nil {
			_, hasAuthField := payload["auth_required"]
			result.HermesCandidate = hasAuthField || hasHermesMarker(body)
			if v, ok := payload["version"].(string); ok {
				result.Version = safeVersion(v)
			}
			if values, ok := payload["auth_providers"].([]any); ok {
				for _, value := range values {
					if name, ok := value.(string); ok && safeProviderName(name) != "" {
						result.AuthProviders = append(result.AuthProviders, safeProviderName(name))
					}
				}
			}
			if v, ok := payload["auth_required"].(bool); ok {
				result.AuthRequired = &v
				if v {
					result.Risk = "auth_gate_present"
					return result
				}
				// `/api/status` is intentionally public. Probe a schema-only
				// route to distinguish local-only status from an open control
				// plane without reading config or sessions.
				schemaStatus, _, schemaErr := getBounded(ctx, client, base+"/api/config/schema", maxStatusBody)
				if schemaErr == nil {
					result.SchemaStatus = schemaStatus
				}
				switch schemaStatus {
				case http.StatusOK:
					result.ControlPlaneUnauthenticated = true
					result.Risk = "critical_unauthenticated_dashboard"
				case http.StatusUnauthorized, http.StatusForbidden:
					result.Risk = "status_local_only_outer_gate"
				default:
					result.Risk = "auth_mode_uncertain"
				}
				// The root and same-origin bundles are public presentation data,
				// not a control-plane secret endpoint. On an exposed control
				// plane, inspect them in memory so a key accidentally embedded in
				// the SPA is reported redacted rather than silently missed.
				if schemaStatus != http.StatusUnauthorized && schemaStatus != http.StatusForbidden {
					_, _ = inspectRoot(ctx, client, base, &result)
				}
				return result
			}
		}
		// A legacy implementation may return a non-JSON status. Keep the
		// candidate signal, but never classify it as a credential exposure.
		result.HermesCandidate = result.HermesCandidate || hasHermesMarker(body)
		result.Risk = "manual_review"
		return result
	}

	// Some deployments put the dashboard behind a normal reverse proxy and do
	// not expose the Hermes JSON status route at all. A root-only fallback lets
	// us identify that deployment and inspect only its public shell/assets. If
	// that shell exposes Hermes' own session marker, the same masked metadata
	// checks as the status path are applied; no reveal/raw endpoint is used.
	for _, endpoint := range probeEndpoints(target, host, port) {
		status, ok := inspectRoot(ctx, client, endpoint.base(), &result)
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			result.URL = result.RootURL
			result.HTTPStatus = status
			result.Reachable = true
			result.Risk = "auth_gate_present"
			return result
		}
		if !ok {
			continue
		}

		result.URL = result.RootURL
		result.HTTPStatus = result.RootStatus
		result.Reachable = true
		if result.RootHermesEvidence {
			result.Risk = "root_dashboard_no_api"
		} else {
			result.Risk = "root_only_manual_review"
		}
		return result
	}
	result.Error = "status endpoint and dashboard root unreachable"
	return result
}

// inspectRoot reads the public root and bounded same-origin static assets. It
// intentionally does not alter URL/HTTPStatus, allowing callers to preserve
// the more meaningful /api/status status when this is an enrichment pass.
func inspectRoot(ctx context.Context, client *http.Client, base string, result *ActiveResult) (int, bool) {
	rootURL := strings.TrimRight(base, "/") + "/"
	status, body, reqErr := getBounded(ctx, client, rootURL, maxStatusBody)
	if reqErr != nil {
		return status, false
	}
	result.RootURL = rootURL
	result.RootStatus = status
	if status < 200 || status >= 300 {
		return status, false
	}
	result.RootHermesEvidence = result.RootHermesEvidence || hasHermesDashboardMarker(body)
	result.HermesCandidate = result.HermesCandidate || result.RootHermesEvidence
	token := extractSessionToken(body)
	if token != "" {
		result.SessionTokenExposed = true
		inspectMaskedEnv(ctx, client, base, token, result)
		inspectMaskedCredentialPool(ctx, client, base, token, result)
		inspectMaskedCustomEndpoints(ctx, client, base, token, result)
	}
	findings := scanPublicBody(ctx, body, rootURL)
	if token != "" {
		findings = classifySessionTokenFinding(findings, rootURL, token)
	}
	result.PublicFindings = append(result.PublicFindings, findings...)
	for _, assetURL := range extractStaticAssets(rootURL, body) {
		if result.StaticAssetsChecked >= maxStaticAssets {
			break
		}
		result.StaticAssetsChecked++
		assetStatus, assetBody, assetErr := getBounded(ctx, client, assetURL, maxAssetBody)
		if assetErr != nil || assetStatus < 200 || assetStatus >= 300 {
			continue
		}
		if hasHermesDashboardMarker(assetBody) {
			result.RootHermesEvidence = true
			result.HermesCandidate = true
		}
		result.PublicFindings = append(result.PublicFindings, scanPublicBody(ctx, assetBody, assetURL)...)
		if len(result.PublicFindings) >= maxPublicFindings {
			result.PublicFindings = result.PublicFindings[:maxPublicFindings]
			break
		}
	}
	return status, true
}

func extractSessionToken(body []byte) string {
	match := sessionTokenRE.FindSubmatch(body)
	if len(match) != 2 {
		return ""
	}
	return string(match[1])
}

// inspectMaskedEnv uses the session token that Hermes itself exposed in the
// public SPA shell only to request /api/env's masked metadata. It never calls
// /api/env/reveal, never reads a value field, and never emits the token.
func inspectMaskedEnv(ctx context.Context, client *http.Client, base, token string, result *ActiveResult) {
	endpoint := strings.TrimRight(base, "/") + "/api/env"
	status, body, err := getMaskedJSON(ctx, client, endpoint, token)
	result.EnvStatus = status
	if err != nil || status != http.StatusOK {
		return
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil {
		return
	}
	for name, raw := range payload {
		if len(result.ConfiguredSecrets) >= maxConfiguredSecrets {
			break
		}
		if !isCredentialEnvName(name) {
			continue
		}
		var metadata struct {
			IsSet bool `json:"is_set"`
		}
		if json.Unmarshal(raw, &metadata) != nil || !metadata.IsSet {
			continue
		}
		if safeMetadataName(name) {
			result.ConfiguredSecrets = append(result.ConfiguredSecrets, ConfiguredSecret{
				Name: name, Present: true, Surface: "env",
			})
		}
	}
	stableConfiguredSecrets(result)
}

// inspectMaskedCredentialPool records only provider/source presence from the
// redacted credential-pool view. The response contains token previews; those
// fields are deliberately ignored and never copied to the report.
func inspectMaskedCredentialPool(ctx context.Context, client *http.Client, base, token string, result *ActiveResult) {
	endpoint := strings.TrimRight(base, "/") + "/api/credentials/pool"
	status, body, err := getMaskedJSON(ctx, client, endpoint, token)
	result.CredentialPoolStatus = status
	if err != nil || status != http.StatusOK {
		return
	}
	var payload struct {
		Providers []struct {
			Provider string `json:"provider"`
			Entries  []struct {
				Source string `json:"source"`
			} `json:"entries"`
		} `json:"providers"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return
	}
	for _, provider := range payload.Providers {
		if !safeMetadataName(provider.Provider) {
			continue
		}
		for _, entry := range provider.Entries {
			if len(result.ConfiguredSecrets) >= maxConfiguredSecrets {
				return
			}
			secret := ConfiguredSecret{
				Name: provider.Provider, Present: true,
				Surface: "credential_pool", Provider: provider.Provider,
			}
			if safeMetadataName(entry.Source) {
				secret.Source = entry.Source
			}
			result.ConfiguredSecrets = append(result.ConfiguredSecrets, secret)
		}
	}
	stableConfiguredSecrets(result)
}

// inspectMaskedCustomEndpoints records only the has_api_key bit for named
// custom endpoints. The endpoint response also carries api_key_preview; it is
// intentionally ignored so even a redaction-format change cannot create a
// secret-bearing report.
func inspectMaskedCustomEndpoints(ctx context.Context, client *http.Client, base, token string, result *ActiveResult) {
	endpoint := strings.TrimRight(base, "/") + "/api/providers/custom-endpoints"
	status, body, err := getMaskedJSON(ctx, client, endpoint, token)
	result.CustomEndpointsStatus = status
	if err != nil || status != http.StatusOK {
		return
	}
	var payload struct {
		Endpoints []struct {
			ID        string `json:"id"`
			HasAPIKey bool   `json:"has_api_key"`
		} `json:"endpoints"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return
	}
	for _, endpoint := range payload.Endpoints {
		if !endpoint.HasAPIKey || !safeMetadataName(endpoint.ID) || len(result.ConfiguredSecrets) >= maxConfiguredSecrets {
			continue
		}
		result.ConfiguredSecrets = append(result.ConfiguredSecrets, ConfiguredSecret{
			Name: endpoint.ID, Present: true, Surface: "config.providers",
		})
	}
	stableConfiguredSecrets(result)
}

func getMaskedJSON(ctx context.Context, client *http.Client, endpoint, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Hermes-Session-Token", token)
	// Never let a session marker follow a redirect, even when an embedding
	// caller supplied an http.Client with permissive redirect behaviour. The
	// normal safehttp client already rejects cross-origin redirects; this extra
	// guard also prevents same-origin redirect chains from expanding the scope.
	requestClient := cloneRequestClient(client, func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	})
	resp, err := requestClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusBody+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if int64(len(body)) > maxStatusBody {
		return resp.StatusCode, nil, errors.New("masked response exceeded bounded audit size")
	}
	return resp.StatusCode, body, nil
}

func stableConfiguredSecrets(result *ActiveResult) {
	// Stable output makes reports diffable without retaining any response data.
	for i := 0; i < len(result.ConfiguredSecrets); i++ {
		for j := i + 1; j < len(result.ConfiguredSecrets); j++ {
			left := result.ConfiguredSecrets[i]
			right := result.ConfiguredSecrets[j]
			if configuredSecretLess(right, left) {
				result.ConfiguredSecrets[i], result.ConfiguredSecrets[j] = result.ConfiguredSecrets[j], result.ConfiguredSecrets[i]
			}
		}
	}
}

func configuredSecretLess(left, right ConfiguredSecret) bool {
	if left.Surface != right.Surface {
		return left.Surface < right.Surface
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	if left.Provider != right.Provider {
		return left.Provider < right.Provider
	}
	return left.Source < right.Source
}

func safeMetadataName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
}

func classifySessionTokenFinding(findings []PublicFinding, path, token string) []PublicFinding {
	fingerprint := model.ComputeFingerprint("generic_high_entropy", path, token)
	for i := range findings {
		if findings[i].Fingerprint != fingerprint {
			continue
		}
		// The token is not a provider key, but it is a privileged dashboard
		// capability. Naming it explicitly prevents operators from mistaking
		// the generic entropy candidate for DEEPSEEK_API_KEY.
		findings[i].Type = "hermes_session_token"
		findings[i].Confidence = 1
		findings[i].Severity = "critical"
	}
	return findings
}

func isCredentialEnvName(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	return strings.Contains(upper, "API_KEY") || strings.Contains(upper, "API-KEY") ||
		strings.Contains(upper, "TOKEN") || strings.Contains(upper, "SECRET") ||
		strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "PRIVATE_KEY")
}

type probeEndpoint struct {
	scheme string
	port   string
	host   string
}

func (e probeEndpoint) base() string {
	return e.scheme + "://" + net.JoinHostPort(e.host, e.port)
}

// probeEndpoints preserves the explicit-port contract while making a bare IP
// useful for dashboards published through a conventional reverse proxy. The
// Hermes native listener remains last so a normal HTTPS/HTTP site wins when
// the operator supplied only an IP.
func probeEndpoints(raw, host, port string) []probeEndpoint {
	if hasExplicitPort(raw) {
		return []probeEndpoint{{scheme: "https", port: port, host: host}, {scheme: "http", port: port, host: host}}
	}
	return []probeEndpoint{
		{scheme: "https", port: "443", host: host},
		{scheme: "http", port: "80", host: host},
		{scheme: "https", port: strconv.Itoa(DefaultPort), host: host},
		{scheme: "http", port: strconv.Itoa(DefaultPort), host: host},
	}
}

func hasExplicitPort(raw string) bool {
	raw = strings.TrimSpace(raw)
	if net.ParseIP(raw) != nil {
		return false
	}
	_, _, err := net.SplitHostPort(raw)
	return err == nil
}

func getBounded(ctx context.Context, client *http.Client, rawURL string, maxBody int64) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.1")
	resp, err := cloneRequestClient(client, client.CheckRedirect).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if int64(len(body)) > maxBody {
		return resp.StatusCode, nil, errors.New("response exceeded bounded audit size")
	}
	return resp.StatusCode, body, nil
}

// cloneRequestClient preserves the transport/timeout supplied by the caller
// while removing any CookieJar. Audit probes are credential-free; a caller's
// ambient browser/session cookie must never be sent to the target.
func cloneRequestClient(client *http.Client, redirect func(*http.Request, []*http.Request) error) *http.Client {
	if client == nil {
		client = safehttp.Client(defaultTimeout)
	}
	return &http.Client{
		Transport:     client.Transport,
		CheckRedirect: redirect,
		Timeout:       client.Timeout,
	}
}

var (
	staticScriptRE = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	staticLinkRE   = regexp.MustCompile(`(?is)<link[^>]+href\s*=\s*["']([^"']+)["']`)
	sessionTokenRE = regexp.MustCompile(`(?is)__HERMES_SESSION_TOKEN__\s*=\s*["']([^"']{16,256})["']`)
	publicScanner  struct {
		once     sync.Once
		detector *detect.Detector
	}
)

// extractStaticAssets returns same-origin script/stylesheet references only.
// Query strings and fragments are dropped so a public HTML page cannot turn
// the audit into a request for a credential-bearing URL. The caller applies a
// hard count and body-size limit before fetching.
func extractStaticAssets(root string, body []byte) []string {
	base, err := url.Parse(root)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}
	refs := append(staticScriptRE.FindAllStringSubmatch(string(body), -1), staticLinkRE.FindAllStringSubmatch(string(body), -1)...)
	seen := map[string]bool{}
	assets := make([]string, 0, len(refs))
	for _, match := range refs {
		if len(match) < 2 {
			continue
		}
		ref := strings.TrimSpace(match[1])
		if ref == "" {
			continue
		}
		asset, err := base.Parse(ref)
		if err != nil || (asset.Scheme != "http" && asset.Scheme != "https") || asset.Host != base.Host || asset.User != nil {
			continue
		}
		asset.RawQuery = ""
		asset.Fragment = ""
		resolved := asset.String()
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		assets = append(assets, resolved)
		if len(assets) >= maxStaticAssets {
			break
		}
	}
	return assets
}

func scanPublicBody(ctx context.Context, body []byte, path string) []PublicFinding {
	publicScanner.once.Do(func() {
		tax, err := taxonomy.LoadDefault()
		if err == nil {
			publicScanner.detector = detect.New(tax)
		}
	})
	if publicScanner.detector == nil || len(body) == 0 {
		return nil
	}
	// This command never has a reveal-secrets flag. Set the process-wide scan
	// guard defensively in case the package is embedded by another caller.
	scan.SetRevealSecrets(false)
	findings := scan.Findings(ctx, publicScanner.detector, nil, nil, model.Item{
		Text: string(body), Source: "code", Path: path,
	}, nil, nil)
	result := make([]PublicFinding, 0, len(findings))
	for _, finding := range findings {
		if finding.Type == scan.ResultsTruncatedType {
			continue
		}
		// Redact once more at this boundary. It is harmless for an already
		// redacted value and guarantees that a hostile embedding cannot turn
		// the audit report into a raw-value sink.
		redacted := model.Redact(finding.Redacted)
		result = append(result, PublicFinding{
			Type: finding.Type, Confidence: finding.Confidence, Severity: finding.Severity,
			Path: finding.Path, Line: finding.Line, Col: finding.Col,
			Redacted: redacted, Fingerprint: finding.Fingerprint,
		})
		if len(result) >= maxPublicFindings {
			break
		}
	}
	return result
}

func parseTarget(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "/") || strings.Contains(raw, "://") {
		return "", "", errors.New("target must be a literal IP with optional port")
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String(), strconv.Itoa(DefaultPort), nil
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", "", errors.New("target must be an IP or IP:port")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", "", errors.New("host must be a literal IP")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", errors.New("port must be between 1 and 65535")
	}
	return ip.String(), strconv.Itoa(n), nil
}

func dedupTargets(targets []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" || strings.HasPrefix(target, "#") || seen[target] {
			continue
		}
		seen[target] = true
		out = append(out, target)
	}
	return out
}

func safeVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 64 {
		v = v[:64]
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return v
}

func safeProviderName(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 32 {
		return ""
	}
	for _, r := range v {
		if r < 0x21 || r > 0x7e {
			return ""
		}
	}
	return v
}

func hasHermesMarker(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "hermes") &&
		(strings.Contains(lower, "9119") || strings.Contains(lower, "auth_required") || strings.Contains(lower, "hermes-agent"))
}

func hasHermesDashboardMarker(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "hermes") &&
		(strings.Contains(lower, "dashboard") || strings.Contains(lower, "9119") || strings.Contains(lower, "auth_required") || strings.Contains(lower, "hermes-agent"))
}

// provider is intentionally private: callers only receive PassiveResult.
type provider interface {
	Lookup(context.Context, string, int) PassiveResult
}

type apiProvider struct {
	name   string
	base   string
	client *http.Client
	lookup func(context.Context, *apiProvider, string, int) PassiveResult
}

func (p *apiProvider) Lookup(ctx context.Context, target string, retries int) PassiveResult {
	return p.lookup(ctx, p, target, retries)
}

func newProviders(client *http.Client, opts Options) []provider {
	requested := map[string]bool{}
	for _, name := range opts.Providers {
		requested[strings.ToLower(strings.TrimSpace(name))] = true
	}
	want := func(name string) bool { return len(requested) == 0 || requested[name] }
	base := func(name, fallback string) string {
		if opts.ProviderURLs != nil && opts.ProviderURLs[name] != "" {
			return strings.TrimRight(opts.ProviderURLs[name], "/")
		}
		return fallback
	}
	var out []provider
	if want("censys") && os.Getenv("CENSYS_API_TOKEN") != "" {
		out = append(out, &apiProvider{name: "censys", base: base("censys", "https://api.platform.censys.io/v3/global"), client: client, lookup: lookupCensys})
	}
	if want("shodan") && os.Getenv("SHODAN_API_KEY") != "" {
		out = append(out, &apiProvider{name: "shodan", base: base("shodan", "https://api.shodan.io"), client: client, lookup: lookupShodan})
	}
	if want("fofa") && os.Getenv("FOFA_EMAIL") != "" && os.Getenv("FOFA_KEY") != "" {
		out = append(out, &apiProvider{name: "fofa", base: base("fofa", "https://fofa.so"), client: client, lookup: lookupFOFA})
	}
	zoomKey := os.Getenv("ZOOMEYE_API_KEY")
	if zoomKey == "" {
		zoomKey = os.Getenv("ZOomeye_API_KEY") // backwards-compatible spelling
	}
	if want("zoomeye") && zoomKey != "" {
		out = append(out, &apiProvider{name: "zoomeye", base: base("zoomeye", "https://api.zoomeye.ai"), client: client, lookup: lookupZoomEye})
	}
	if want("leakix") && os.Getenv("LEAKIX_API_KEY") != "" {
		out = append(out, &apiProvider{name: "leakix", base: base("leakix", "https://leakix.net"), client: client, lookup: lookupLeakIX})
	}
	return out
}

func lookupCensys(ctx context.Context, p *apiProvider, target string, retries int) PassiveResult {
	ip, _, err := parseTarget(target)
	if err != nil {
		return providerError(p.name, target, err)
	}
	path := "/asset/host/" + url.PathEscape(ip)
	h := map[string]string{"Authorization": "Bearer " + os.Getenv("CENSYS_API_TOKEN")}
	return p.get(ctx, target, path, nil, h, retries)
}

func lookupShodan(ctx context.Context, p *apiProvider, target string, retries int) PassiveResult {
	ip, _, err := parseTarget(target)
	if err != nil {
		return providerError(p.name, target, err)
	}
	q := url.Values{"key": []string{os.Getenv("SHODAN_API_KEY")}}
	return p.get(ctx, target, "/shodan/host/"+url.PathEscape(ip), q, nil, retries)
}

func lookupFOFA(ctx context.Context, p *apiProvider, target string, retries int) PassiveResult {
	ip, _, err := parseTarget(target)
	if err != nil {
		return providerError(p.name, target, err)
	}
	query := base64.StdEncoding.EncodeToString([]byte(`ip="` + ip + `"`))
	q := url.Values{
		"email":   []string{os.Getenv("FOFA_EMAIL")},
		"key":     []string{os.Getenv("FOFA_KEY")},
		"qbase64": []string{query},
		"fields":  []string{"host,ip,port,title,server,protocol,update_time"},
		"size":    []string{"1"},
		"page":    []string{"1"},
		"full":    []string{"false"},
	}
	return p.get(ctx, target, "/api/v1/search/all", q, nil, retries)
}

func lookupZoomEye(ctx context.Context, p *apiProvider, target string, retries int) PassiveResult {
	ip, _, err := parseTarget(target)
	if err != nil {
		return providerError(p.name, target, err)
	}
	query := base64.StdEncoding.EncodeToString([]byte(`ip="` + ip + `"`))
	body, err := json.Marshal(map[string]any{
		"qbase64": query, "page": 1, "pagesize": 1,
		"fields": "ip,port,domain,title,service,update_time", "sub_type": "all",
	})
	if err != nil {
		return providerError(p.name, target, err)
	}
	key := os.Getenv("ZOOMEYE_API_KEY")
	if key == "" {
		key = os.Getenv("ZOomeye_API_KEY")
	}
	h := map[string]string{"API-KEY": key, "Content-Type": "application/json"}
	return p.post(ctx, target, "/v2/search", body, h, retries)
}

func lookupLeakIX(ctx context.Context, p *apiProvider, target string, retries int) PassiveResult {
	ip, _, err := parseTarget(target)
	if err != nil {
		return providerError(p.name, target, err)
	}
	h := map[string]string{"api-key": os.Getenv("LEAKIX_API_KEY")}
	return p.get(ctx, target, "/host/"+url.PathEscape(ip), nil, h, retries)
}

func providerError(name, target string, err error) PassiveResult {
	return PassiveResult{Provider: name, Target: target, Status: "error", Error: safeError(err), ObservedAt: time.Now().UTC()}
}

func (p *apiProvider) get(ctx context.Context, target, path string, query url.Values, headers map[string]string, retries int) PassiveResult {
	endpoint := p.base + path
	return p.request(ctx, target, endpoint, query, headers, nil, retries)
}

func (p *apiProvider) post(ctx context.Context, target, path string, body []byte, headers map[string]string, retries int) PassiveResult {
	endpoint := p.base + path
	return p.request(ctx, target, endpoint, nil, headers, body, retries)
}

func (p *apiProvider) request(ctx context.Context, target, endpoint string, query url.Values, headers map[string]string, body []byte, retries int) PassiveResult {
	result := PassiveResult{Provider: p.name, Target: target, Endpoint: endpoint, ObservedAt: time.Now().UTC()}
	if retries < 0 {
		retries = defaultRetries
	}
	for attempt := 0; attempt <= retries; attempt++ {
		reqURL := endpoint
		if len(query) > 0 {
			reqURL += "?" + query.Encode()
		}
		method := http.MethodGet
		var reader io.Reader
		if body != nil {
			method = http.MethodPost
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, reqURL, reader)
		if err != nil {
			result.Status = "error"
			result.Error = safeError(err)
			return result
		}
		req.Header.Set("User-Agent", providerUserAgent)
		req.Header.Set("Accept", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := p.client.Do(req)
		if err != nil {
			if attempt < retries && ctx.Err() == nil {
				if !waitBackoff(ctx, attempt, 0) {
					break
				}
				continue
			}
			result.Status = "error"
			result.Error = safeError(err)
			return result
		}
		result.HTTPStatus = resp.StatusCode
		limitedFor := parseRetryAfter(resp.Header)
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxProviderBody+1))
		_ = resp.Body.Close()
		if readErr != nil {
			result.Status = "error"
			result.Error = safeError(readErr)
			return result
		}
		if int64(len(data)) > maxProviderBody {
			result.Status = "error"
			result.Error = "provider response exceeded bounded audit size"
			return result
		}
		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			result.Status = "rate_limited"
			result.RetryAfter = limitedFor.String()
			if attempt < retries && limitedFor <= maxRetryDelay && waitBackoff(ctx, attempt, limitedFor) {
				continue
			}
			return result
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			result.Status = "unauthorized"
			return result
		case resp.StatusCode == http.StatusNotFound:
			result.Status = "not_found"
			return result
		case resp.StatusCode < 200 || resp.StatusCode >= 300:
			if attempt < retries && resp.StatusCode >= 500 && waitBackoff(ctx, attempt, limitedFor) {
				continue
			}
			result.Status = "error"
			result.Error = fmt.Sprintf("provider returned HTTP %d", resp.StatusCode)
			return result
		default:
			result.Status = "found"
			result.HermesEvidence, result.Ports = summarizePayload(data)
			return result
		}
	}
	result.Status = "error"
	result.Error = "request cancelled or retries exhausted"
	return result
}

func parseRetryAfter(h http.Header) time.Duration {
	for _, name := range []string{"Retry-After", "X-RateLimit-Reset", "x-limited-for"} {
		value := strings.TrimSpace(h.Get(name))
		if value == "" {
			continue
		}
		if name == "x-limited-for" {
			if d, err := time.ParseDuration(value); err == nil && d >= 0 {
				return minDuration(d, maxRetryDelay)
			}
		}
		if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
			if name == "X-RateLimit-Reset" && seconds > time.Now().Unix() {
				return minDuration(time.Until(time.Unix(seconds, 0)), maxRetryDelay)
			}
			return minDuration(time.Duration(seconds)*time.Second, maxRetryDelay)
		}
		if when, err := http.ParseTime(value); err == nil {
			return minDuration(time.Until(when), maxRetryDelay)
		}
	}
	return 0
}

func waitBackoff(ctx context.Context, attempt int, serverDelay time.Duration) bool {
	delay := serverDelay
	if delay <= 0 {
		base := 250 * time.Millisecond
		shift := attempt
		if shift > 6 {
			shift = 6
		}
		delay = base * time.Duration(1<<shift)
		// Small jitter prevents synchronized retries without hiding a rate limit.
		delay += time.Duration(rand.Int63n(int64(100 * time.Millisecond)))
	}
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < 0 {
		return 0
	}
	if a > b {
		return b
	}
	return a
}

func summarizePayload(data []byte) (bool, []int) {
	lower := strings.ToLower(string(data))
	hermes := strings.Contains(lower, "hermes") &&
		(strings.Contains(lower, "9119") || strings.Contains(lower, "auth_required") || strings.Contains(lower, "hermes-agent"))
	var value any
	if json.Unmarshal(data, &value) != nil {
		return hermes, nil
	}
	ports := map[int]bool{}
	collectPorts(value, ports)
	out := make([]int, 0, len(ports))
	for port := range ports {
		if port > 0 && port <= 65535 {
			out = append(out, port)
		}
	}
	// Keep output deterministic without importing a sorting-heavy report path.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return hermes, out
}

func collectPorts(v any, ports map[int]bool) {
	switch x := v.(type) {
	case map[string]any:
		for key, child := range x {
			if strings.EqualFold(key, "port") || strings.HasSuffix(strings.ToLower(key), ".port") {
				switch n := child.(type) {
				case float64:
					if n == math.Trunc(n) {
						ports[int(n)] = true
					}
				case string:
					if n, err := strconv.Atoi(n); err == nil {
						ports[n] = true
					}
				}
			}
			collectPorts(child, ports)
		}
	case []any:
		for _, child := range x {
			collectPorts(child, ports)
		}
	}
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(err.Error())
	if len(text) > 240 {
		text = text[:240]
	}
	// Do not let a provider URL or a body fragment become an accidental secret
	// sink in logs/reports.
	if i := strings.IndexByte(text, '?'); i >= 0 {
		text = text[:i] + "?[redacted query]"
	}
	text = strings.ReplaceAll(text, "&key=", "&key=[redacted]")
	text = strings.ReplaceAll(text, "Authorization", "[authorization]")
	return text
}
