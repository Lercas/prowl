// Package credentialset holds bounded, ephemeral components from one completed
// acquisition. It never persists plaintext or submits credentials to a provider.
package credentialset

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var (
	ErrInvalid    = errors.New("invalid credential component")
	ErrLimit      = errors.New("credential component budget exceeded")
	ErrIncomplete = errors.New("credential component acquisition is incomplete")
	ErrUnsealed   = errors.New("credential components are not sealed")
	ErrSealed     = errors.New("credential components are sealed")
	ErrClosed     = errors.New("credential components are closed")
	ErrAmbiguous  = errors.New("credential components are missing, ambiguous or invalid")
	ErrPrivate    = errors.New("credential components cannot be serialized")
)

// Scope is an opaque acquisition/revision boundary, independent of display names
// or operator-selected persistent index labels. Reuse only within that boundary.
type Scope struct{ _ byte }

func NewScope() *Scope { return &Scope{} }

// Limits bound retained observations, including repeated identical values.
type Limits struct {
	Observations int
	Bytes        int
}

type observation struct {
	name, value, location string
}

// Set is owned by one scan invocation. A fresh set is required for the next run.
// Invalid observations/budget exhaustion poison the set rather than allowing a
// partial inventory to appear unambiguous. Close releases all retained references;
// Go strings do not provide a cryptographic memory-erasure guarantee.
type Set struct {
	mu       sync.Mutex
	limits   Limits
	count    int
	bytes    int
	sealed   bool
	closed   bool
	failure  error
	observed map[*Scope][]observation
}

func New(limits Limits) (*Set, error) {
	if limits.Observations <= 0 || limits.Observations > 100000 || limits.Bytes <= 0 || limits.Bytes > 32<<20 {
		return nil, ErrInvalid
	}
	return &Set{limits: limits, observed: make(map[*Scope][]observation)}, nil
}

// String/GoString keep accidental formatting from disclosing internal values.
func (*Set) String() string   { return "credentialset.Set{redacted}" }
func (*Set) GoString() string { return "credentialset.Set{redacted}" }

// MarshalJSON rejects persistence even when a caller accidentally serializes its
// enclosing request/state object. The error never includes an observed value.
func (*Set) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }

var separators = strings.NewReplacer("_", "", "-", "", ".", "")

func normalized(name string) string { return separators.Replace(strings.ToLower(name)) }

func validName(name string) bool {
	if len(name) == 0 || len(name) > 128 || normalized(name) == "" {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// Observe accepts only parser-established named literals. location is an opaque
// location identity, never a source path or raw source text. Values are copied to
// avoid retaining a whole source buffer through a substring.
func (s *Set) Observe(ctx context.Context, scope *Scope, name, value, location string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.state(ctx); err != nil {
		return err
	}
	if s.sealed {
		return ErrSealed
	}
	if scope == nil || !validName(name) || value == "" || len(value) > 65536 || location == "" || len(location) > 256 {
		s.failure = ErrInvalid
		return s.failure
	}
	retained := len(name) + len(value) + len(location)
	if s.count >= s.limits.Observations || retained > s.limits.Bytes-s.bytes {
		s.failure = ErrLimit
		return s.failure
	}
	s.observed[scope] = append(s.observed[scope], observation{normalized(name), strings.Clone(value), strings.Clone(location)})
	s.count++
	s.bytes += retained
	return nil
}

func (s *Set) state(ctx context.Context) error {
	if s.closed {
		return ErrClosed
	}
	if s.failure != nil {
		return s.failure
	}
	if ctx.Err() != nil {
		s.failure = ErrIncomplete
		return s.failure
	}
	return nil
}

// Seal must follow a complete source drain. False also covers source errors,
// truncation, cancellation, or untrusted/unparsed component coverage.
func (s *Set) Seal(ctx context.Context, complete bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.state(ctx); err != nil {
		return err
	}
	if !complete {
		s.failure = ErrIncomplete
		return s.failure
	}
	s.sealed = true
	return nil
}

// Field names/aliases are explicit roles; Pattern validates the complete literal.
// Matching never searches a value for a token or tries credential combinations.
type Field struct {
	Name    string
	Aliases []string
	Pattern string
}

type field struct {
	name    string
	aliases map[string]bool
	pattern *regexp.Regexp
}

// Schema snapshots provider requirements. Alias overlap across roles is rejected.
type Schema struct{ fields []field }

func NewSchema(fields []Field) (*Schema, error) {
	if len(fields) == 0 || len(fields) > 128 {
		return nil, ErrInvalid
	}
	out := &Schema{}
	owners := make(map[string]bool)
	for _, f := range fields {
		if !validName(f.Name) || len(f.Aliases) > 32 || len(f.Pattern) == 0 || len(f.Pattern) > 4096 {
			return nil, ErrInvalid
		}
		re, err := regexp.Compile("\\A(?:" + f.Pattern + ")\\z")
		if err != nil {
			return nil, ErrInvalid
		}
		entry := field{name: strings.Clone(f.Name), pattern: re, aliases: make(map[string]bool)}
		for _, alias := range append([]string{f.Name}, f.Aliases...) {
			if !validName(alias) {
				return nil, ErrInvalid
			}
			alias = normalized(alias)
			if owners[alias] && !entry.aliases[alias] {
				return nil, ErrInvalid
			}
			entry.aliases[alias], owners[alias] = true, true
		}
		out.fields = append(out.fields, entry)
	}
	return out, nil
}

// With resolves all required roles around a primary component which was actually
// observed in this scope. Use receives a temporary map; it must not retain values.
// Locations are sorted/deduplicated evidence IDs, including repeated observations.
// Neither this method nor the set performs provider I/O.
func (s *Set) With(ctx context.Context, scope *Scope, schema *Schema, primaryName, primaryValue string, use func(values map[string]string, locations map[string][]string) error) error {
	values, locations, err := s.resolve(ctx, scope, schema, primaryName, primaryValue)
	if err != nil {
		return err
	}
	defer clear(values)
	defer clear(locations)
	if ctx.Err() != nil {
		return ErrIncomplete
	}
	if use == nil {
		return ErrInvalid
	}
	return use(values, locations)
}

func (s *Set) resolve(ctx context.Context, scope *Scope, schema *Schema, primaryName, primaryValue string) (map[string]string, map[string][]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.state(ctx); err != nil {
		return nil, nil, err
	}
	if !s.sealed {
		return nil, nil, ErrUnsealed
	}
	if scope == nil || schema == nil || len(schema.fields) == 0 || !validName(primaryName) {
		return nil, nil, ErrInvalid
	}
	values := make(map[string]string)
	locations := make(map[string][]string)
	anchored := false
	for _, f := range schema.fields {
		places := make(map[string]bool)
		for i, o := range s.observed[scope] {
			if i%256 == 0 && ctx.Err() != nil {
				s.failure = ErrIncomplete
				return nil, nil, s.failure
			}
			if !f.aliases[o.name] {
				continue
			}
			if !f.pattern.MatchString(o.value) || (values[f.name] != "" && values[f.name] != o.value) {
				return nil, nil, ErrAmbiguous
			}
			values[f.name], places[o.location] = o.value, true
		}
		if values[f.name] == "" {
			return nil, nil, ErrAmbiguous
		}
		if f.aliases[normalized(primaryName)] {
			if values[f.name] != primaryValue {
				return nil, nil, ErrAmbiguous
			}
			anchored = true
		}
		for p := range places {
			locations[f.name] = append(locations[f.name], p)
		}
		sort.Strings(locations[f.name])
	}
	if !anchored {
		return nil, nil, ErrAmbiguous
	}
	return values, locations, nil
}

func (s *Set) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.observed)
	s.observed = nil
	s.closed = true
}
