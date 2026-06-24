package atlassian

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// Deployment describes a detected Atlassian instance and the API shape the walker must use.
type Deployment struct {
	Product    string // "jira" | "confluence"
	Kind       string // "cloud" | "server" | "datacenter"
	BaseURL    string // normalized, no trailing slash (may include a context path)
	WikiPrefix string // "/wiki" on Confluence Cloud; "" on Confluence Server/DC (Jira: always "")
	Version    string // e.g. "9.4.0" for Server/DC; "" for Cloud (continuously deployed)
	CloudV1    bool   // Confluence Cloud where only the legacy v1 API answered (v2 absent; pre-2025-03-31)
}

// Cloud reports whether the deployment is Atlassian Cloud (vs self-hosted Server / Data Center).
func (d Deployment) Cloud() bool { return d.Kind == "cloud" }

// String renders a short human label for logs.
func (d Deployment) String() string {
	s := d.Product + " " + d.Kind
	if d.Version != "" {
		s += " " + d.Version
	}
	return s
}

// jiraServerInfo is the subset of /rest/api/2/serverInfo used to classify a Jira instance.
type jiraServerInfo struct {
	BaseURL        string `json:"baseUrl"`
	Version        string `json:"version"`
	DeploymentType string `json:"deploymentType"` // "Cloud" | "Server" | "DataCenter"
}

// DetectJira classifies a Jira base URL. It prefers the authoritative /rest/api/2/serverInfo
// .deploymentType (present on ALL deployments); it never decides on hostname alone (T1). A 401/403
// means the instance exists but the credential was rejected — not that it is Server/DC (T2).
func DetectJira(ctx context.Context, c *Client) (Deployment, error) {
	var info jiraServerInfo
	d := Deployment{Product: "jira", BaseURL: c.base}
	if err := c.get(ctx, "/rest/api/2/serverInfo", nil, &info); err != nil {
		return d, err
	}
	switch strings.ToLower(info.DeploymentType) {
	case "cloud":
		d.Kind = "cloud"
	case "datacenter":
		d.Kind = "datacenter"
	case "server":
		d.Kind = "server"
	default:
		// Empty/unknown deploymentType — some reverse proxies strip the field. Don't blindly assume
		// Server/DC (which would route a Cloud instance to /rest/api/2 and the wrong search path):
		// fall back to the host shape. Atlassian Cloud is always *.atlassian.net / *.jira.com.
		d.Kind = "server"
		if isAtlassianCloudHost(info.BaseURL) || isAtlassianCloudHost(c.base) {
			d.Kind = "cloud"
		}
	}
	d.Version = info.Version
	return d, nil
}

// isAtlassianCloudHost reports whether a URL's host is an Atlassian Cloud tenant — used ONLY as a
// last-resort fallback when serverInfo omits deploymentType (never as the primary signal, T1).
func isAtlassianCloudHost(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return strings.HasSuffix(host, ".atlassian.net") || strings.HasSuffix(host, ".jira.com")
}

// DetectConfluence classifies a Confluence base URL by PROBING the path shape — Confluence exposes
// no deploymentType field (T3). Cloud serves /wiki/api/v2 (and legacy /wiki/rest/api); Server/DC
// serves /rest/api/* with NO /wiki prefix. We probe cheaply (limit=1) and accept 200 OR an
// auth-gated 401/403 as proof the shape exists, so a missing token still yields a classification.
func DetectConfluence(ctx context.Context, c *Client) (Deployment, error) {
	d := Deployment{Product: "confluence", BaseURL: c.base}
	probes := []struct {
		path       string
		kind       string
		wikiPrefix string
		cloudV1    bool
	}{
		{"/wiki/api/v2/spaces", "cloud", "/wiki", false}, // Cloud v2 (current)
		{"/wiki/rest/api/space", "cloud", "/wiki", true}, // Cloud v1 only (legacy, removed 2025-03-31)
		{"/rest/api/space", "server", "", false},         // Server / Data Center (no /wiki prefix)
	}
	params := url.Values{"limit": {"1"}}
	var lastErr error
	for _, p := range probes {
		err := c.get(ctx, p.path, params, nil)
		switch {
		case err == nil || statusOf(err) == 401 || statusOf(err) == 403:
			// 200 or an auth-gated 401/403 both mean this path shape exists on the instance.
			d.Kind, d.WikiPrefix, d.CloudV1 = p.kind, p.wikiPrefix, p.cloudV1
			return d, nil
		case statusOf(err) == 404:
			lastErr = err // this shape is genuinely absent — try the next probe
		default:
			// 429 / 5xx / network: the server is up but cannot answer right now. Do NOT fall through and
			// risk classifying the deployment from a later probe — abort so the caller retries.
			return d, fmt.Errorf("confluence deployment detection inconclusive at %s (transient/error): %w", p.path, err)
		}
	}
	return d, lastErr
}
