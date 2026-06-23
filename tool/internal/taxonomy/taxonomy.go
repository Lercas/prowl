// Package taxonomy loads references/secret_taxonomy.yaml and compiles its detection regexes.
package taxonomy

import (
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/Lercas/prowl/tool/internal/saferegex"
	"gopkg.in/yaml.v3"
)

// MaxFileSize caps how many bytes an untrusted taxonomy / gitleaks / trufflehog file may occupy.
// A 1 GB rule file would otherwise be slurped whole into memory before parsing. Real rulesets are a
// few hundred KB at most, so 16 MiB leaves ample headroom while refusing an oversized DoS payload.
const MaxFileSize = 16 << 20 // 16 MiB

// readCapped reads path but refuses a file larger than MaxFileSize, so an attacker-committed rule
// file can't OOM the loader before parsing even begins. It uses Stat for the cheap up-front rejection
// and a bounded io.LimitReader as a guard against a file that grows between Stat and read.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > MaxFileSize {
		return nil, fmt.Errorf("file %s too large (%d bytes > %d limit)", path, fi.Size(), MaxFileSize)
	}
	// LimitReader to MaxFileSize+1 catches a file that grew past the cap after the Stat check.
	raw, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > MaxFileSize {
		return nil, fmt.Errorf("file %s too large (> %d limit)", path, MaxFileSize)
	}
	return raw, nil
}

type Detection struct {
	Regex    string   `yaml:"regex"`
	Prefixes []string `yaml:"prefixes"`
	Charset  string   `yaml:"charset"`
}

type Checksum struct {
	Present   bool   `yaml:"present"`
	Algorithm string `yaml:"algorithm"`
}

type SecretType struct {
	ID         string    `yaml:"id"`
	Name       string    `yaml:"name"`
	Category   string    `yaml:"category"`
	Sensitive  bool      `yaml:"sensitive"`
	Detection  Detection `yaml:"detection"`
	Checksum   Checksum  `yaml:"checksum"`
	Verifiable bool      `yaml:"verifiable"`

	// Keywords/Entropy are populated for imported (gitleaks/trufflehog) rules.
	Keywords []string `yaml:"keywords,omitempty"`
	Entropy  float64  `yaml:"entropy,omitempty"`
	Source   string   `yaml:"-"` // "", "gitleaks", or "trufflehog"

	// Extract is the 1-based capture group whose span is the secret value (gitleaks secretGroup).
	// 0 means "default": prefer capture group 1 if present, else the whole match.
	Extract int `yaml:"extract,omitempty"`

	RE *regexp.Regexp `yaml:"-"`
}

type Taxonomy struct {
	Version int          `yaml:"version"`
	Types   []SecretType `yaml:"types"`

	Skipped []string `yaml:"-"` // ids whose regex failed to compile
}

// Load reads the taxonomy and compiles each type's regex; uncompilable patterns go to Skipped.
func Load(path string) (*Taxonomy, error) {
	raw, err := readCapped(path)
	if err != nil {
		return nil, fmt.Errorf("read taxonomy: %w", err)
	}
	var t Taxonomy
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("parse taxonomy: %w", err)
	}
	compiled := t.Types[:0]
	for _, st := range t.Types {
		// Taxonomy regexes are attacker-controlled (a committed --taxonomy YAML), so guard against a
		// regex-bomb via saferegex; an oversized/absurdly-bounded one is skipped, not OOM-inducing.
		re, err := saferegex.Compile(st.Detection.Regex)
		if err != nil {
			t.Skipped = append(t.Skipped, st.ID)
			continue
		}
		st.RE = re
		compiled = append(compiled, st)
	}
	t.Types = compiled
	return &t, nil
}

// GenericLast holds catch-all types scored lower and tried after structured ones.
var GenericLast = map[string]bool{
	"generic_api_key": true, "generic_high_entropy": true,
	"generic_password": true, "basic_auth_header": true,
}
