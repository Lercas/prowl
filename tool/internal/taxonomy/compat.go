package taxonomy

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Lercas/prowl/tool/internal/saferegex"
	"gopkg.in/yaml.v3"
)

// Allowlist is a portable allow-set merged from an imported config.
type Allowlist struct {
	Regexes   []string
	Paths     []string
	StopWords []string
}

type glAllowlist struct {
	Description string   `toml:"description"`
	Regexes     []string `toml:"regexes"`
	Paths       []string `toml:"paths"`
	StopWords   []string `toml:"stopwords"`
}

type glRule struct {
	ID          string        `toml:"id"`
	Description string        `toml:"description"`
	Regex       string        `toml:"regex"`
	Path        string        `toml:"path"`
	Keywords    []string      `toml:"keywords"`
	Entropy     float64       `toml:"entropy"`
	SecretGroup int           `toml:"secretGroup"`
	Allowlist   glAllowlist   `toml:"allowlist"`
	Allowlists  []glAllowlist `toml:"allowlists"`
}

type glConfig struct {
	Title      string        `toml:"title"`
	Rules      []glRule      `toml:"rules"`
	Allowlist  glAllowlist   `toml:"allowlist"`
	Allowlists []glAllowlist `toml:"allowlists"`
}

// LoadGitleaks parses a gitleaks .toml ruleset into Prowl types and a merged allowlist.
func LoadGitleaks(path string) (*Taxonomy, *Allowlist, error) {
	// Read with a size cap before decoding so a 1 GB committed .gitleaks.toml can't be slurped whole
	// (toml.DecodeFile would otherwise read the entire file into memory).
	raw, err := readCapped(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read gitleaks config %s: %w", path, err)
	}
	var c glConfig
	if _, err := toml.Decode(string(raw), &c); err != nil {
		return nil, nil, fmt.Errorf("parse gitleaks config %s: %w", path, err)
	}
	t := &Taxonomy{}
	al := &Allowlist{}
	for _, r := range c.Rules {
		if r.Regex == "" {
			continue
		}
		t.Types = append(t.Types, SecretType{
			ID:        sanitizeID(r.ID),
			Name:      orElse(r.Description, r.ID),
			Category:  inferCategory(r.ID),
			Sensitive: true,
			Detection: Detection{Regex: r.Regex},
			Keywords:  lower(r.Keywords),
			Entropy:   r.Entropy,
			Source:    "gitleaks",
			// gitleaks secretGroup selects which capture group is the secret value; 0/1 keep the
			// engine's default extraction (group 1 if present, else whole match).
			Extract: r.SecretGroup,
		})
		mergeGL(al, r.Allowlist)
		for _, a := range r.Allowlists {
			mergeGL(al, a)
		}
	}
	mergeGL(al, c.Allowlist)
	for _, a := range c.Allowlists {
		mergeGL(al, a)
	}
	return compileAll(t), al, nil
}

func mergeGL(dst *Allowlist, a glAllowlist) {
	dst.Regexes = append(dst.Regexes, a.Regexes...)
	dst.Paths = append(dst.Paths, a.Paths...)
	dst.StopWords = append(dst.StopWords, a.StopWords...)
}

type thDetector struct {
	Name     string            `yaml:"name"`
	Keywords []string          `yaml:"keywords"`
	Regex    map[string]string `yaml:"regex"`
}

type thConfig struct {
	Detectors []thDetector `yaml:"detectors"`
}

// LoadTrufflehog parses a trufflehog custom-detectors YAML into Prowl types (one rule per regex).
func LoadTrufflehog(path string) (*Taxonomy, error) {
	raw, err := readCapped(path)
	if err != nil {
		return nil, err
	}
	var c thConfig
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse trufflehog config %s: %w", path, err)
	}
	t := &Taxonomy{}
	for _, d := range c.Detectors {
		for name, rx := range d.Regex {
			if rx == "" {
				continue
			}
			id := sanitizeID(d.Name)
			if len(d.Regex) > 1 {
				id += "_" + sanitizeID(name)
			}
			t.Types = append(t.Types, SecretType{
				ID:        id,
				Name:      d.Name,
				Category:  inferCategory(d.Name),
				Sensitive: true,
				Detection: Detection{Regex: rx},
				Keywords:  lower(d.Keywords),
				Source:    "trufflehog",
			})
		}
	}
	return compileAll(t), nil
}

// LoadAny auto-detects the format: .toml is gitleaks, YAML with a top-level detectors: key is
// trufflehog, otherwise Prowl's own taxonomy YAML.
func LoadAny(path string) (*Taxonomy, *Allowlist, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".toml" {
		return LoadGitleaks(path)
	}
	raw, err := readCapped(path)
	if err != nil {
		return nil, nil, err
	}
	if rxDetectorsKey.Match(raw) {
		t, err := LoadTrufflehog(path)
		return t, &Allowlist{}, err
	}
	t, err := Load(path)
	return t, &Allowlist{}, err
}

var rxDetectorsKey = regexp.MustCompile(`(?m)^detectors:`)

func compileAll(t *Taxonomy) *Taxonomy {
	compiled := t.Types[:0]
	for _, st := range t.Types {
		// gitleaks/trufflehog regexes are attacker-controlled (a committed .gitleaks.toml is
		// auto-loaded), so guard against a regex-bomb via saferegex rather than bare regexp.Compile.
		re, err := saferegex.Compile(st.Detection.Regex)
		if err != nil {
			t.Skipped = append(t.Skipped, st.ID)
			continue
		}
		st.RE = re
		compiled = append(compiled, st)
	}
	t.Types = compiled
	return t
}

var rxNonID = regexp.MustCompile(`[^a-z0-9_]+`)

func sanitizeID(s string) string {
	s = rxNonID.ReplaceAllString(strings.ToLower(s), "_")
	return strings.Trim(s, "_")
}

func lower(xs []string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, strings.ToLower(x))
	}
	return out
}

func orElse(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// inferCategory maps a rule id/name to a Prowl category, which drives severity.
func inferCategory(id string) string {
	l := strings.ToLower(id)
	switch {
	case containsAny(l, "aws", "azure", "gcp", "cloud", "digitalocean", "heroku"):
		return "cloud"
	case containsAny(l, "github", "gitlab", "bitbucket"):
		return "vcs"
	case containsAny(l, "private", "rsa", "pgp", "pki", "certificate"):
		return "pki"
	case containsAny(l, "stripe", "paypal", "square", "payment"):
		return "payment"
	case containsAny(l, "openai", "anthropic", "cohere", "huggingface"):
		return "ai"
	case containsAny(l, "postgres", "mysql", "mongo", "redis", "database"):
		return "db"
	}
	return "generic"
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
