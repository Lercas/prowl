package scan

import (
	"fmt"
	"github.com/Lercas/prowl/tool/internal/model"
	"net/url"
	"sort"
	"strings"
)

func (p *Pipeline) findingDedupKey(line, col int, value string) string {
	if p.options.ValueFingerprint != nil || p.options.AllOccurrences {
		return fmt.Sprintf("%d:%d:%s", line, col, value)
	}
	return fmt.Sprintf("%d:%s", line, value)
}

func (p *Pipeline) observeVerification(f model.Finding) {
	if f.Verified == nil || f.ValueFingerprint == "" || p.options.ObserveVerification == nil {
		return
	}
	verified := *f.Verified
	p.options.ObserveVerification(model.Finding{Type: f.IndexType, ValueFingerprint: f.ValueFingerprint, IndexLocationID: f.IndexLocationID, IndexType: f.IndexType, IndexSource: f.IndexSource, IndexPath: f.IndexPath, Line: f.Line, Col: f.Col, Verified: &verified})
}

func (p *Pipeline) valueFingerprint(raw string) string {
	if p.options.ValueFingerprint == nil {
		return ""
	}
	return p.options.ValueFingerprint(raw)
}

func (p *Pipeline) locationFingerprint(source, path string, line, col int) string {
	if p.options.LocationFingerprint == nil {
		return ""
	}
	return p.options.LocationFingerprint(source, path, line, col)
}

func publicIdentityPath(it model.Item) string {
	if it.IdentityPath != "" && it.ArtifactURI != "" {
		return it.ArtifactURI
	}
	return it.Path
}

func privateIdentityPath(it model.Item) string {
	if it.IdentityPath != "" {
		return it.IdentityPath
	}
	return it.Path
}

func (p *Pipeline) itemLocationFingerprint(it model.Item, line, col int) string {
	path := privateIdentityPath(it)
	if it.MobileEntry > 0 {
		path += fmt.Sprintf("\x00mobile-entry\x00%d", it.MobileEntry)
	}
	return p.locationFingerprint(it.Source, path, line, col)
}

func (p *Pipeline) indexText(text, raw string) string {
	if p.options.ValueFingerprint == nil {
		return ""
	}
	if raw != "" {
		return strings.ReplaceAll(text, raw, "[REDACTED]")
	}
	return text
}

// sanitizeIndexMetadata removes every detected value from every metadata row,
// including values suppressed by allowlists. Original coordinates are HMACed
// separately; display sanitization must not collapse their identities.
func (p *Pipeline) sanitizeIndexMetadata(findings []model.Finding, values []string) {
	if p.options.ValueFingerprint == nil || len(findings) == 0 {
		return
	}
	maxLength := 0
	for _, f := range findings {
		maxLength = max(maxLength, len(f.IndexPath), len(f.IndexSource), len(f.IndexType))
	}
	unique := make(map[string]bool)
	var literals []string
	for _, value := range values {
		if value != "" && len(value) <= maxLength && !unique[value] {
			unique[value] = true
			literals = append(literals, value)
		}
	}
	sort.Slice(literals, func(i, j int) bool { return len(literals[i]) > len(literals[j]) })
	pairs := make([]string, 0, 2*len(literals))
	for _, value := range literals {
		pairs = append(pairs, value, "[REDACTED]")
	}
	replace := strings.NewReplacer(pairs...).Replace
	cache := make(map[string]string)
	clean := func(text string) string {
		if result, ok := cache[text]; ok {
			return result
		}
		result := replace(text)
		if strings.Contains(text, "://") {
			if u, err := url.Parse(text); err == nil {
				u.User, u.RawQuery = nil, ""
				if u.Scheme == "mobile+file" || u.Scheme == "mobile+payload" || u.Scheme == "mobile+http" || u.Scheme == "mobile+https" || u.Scheme == "web+http" || u.Scheme == "web+https" {
					// Synthetic fragments locate source-declared views, not request data.
					u.Fragment, u.RawFragment = replace(u.Fragment), ""
				} else {
					u.Fragment, u.RawFragment = "", ""
				}
				u.ForceQuery = false
				u.Path, u.Host, u.Opaque = replace(u.Path), replace(u.Host), replace(u.Opaque)
				u.RawPath = ""
				result = replace(u.String())
			} else {
				result = "[unparseable URL location]"
			}
		}
		cache[text] = result
		return result
	}
	for i := range findings {
		findings[i].IndexPath = clean(findings[i].IndexPath)
		findings[i].IndexSource = clean(findings[i].IndexSource)
		findings[i].IndexType = clean(findings[i].IndexType)
	}
}
