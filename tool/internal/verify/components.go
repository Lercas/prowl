package verify

import (
	"context"
	"regexp"
	"sort"

	"github.com/Lercas/prowl/tool/internal/credentialset"
)

// ComponentEvidence identifies roles without echoing a source-supplied property
// name, which may itself contain another credential.
type ComponentEvidence = credentialset.Evidence

// VerifyComponents uses a sealed, current-acquisition inventory instead of
// searching unrelated source context. The caller must establish the primary's
// property name through a parser, not infer it from the credential type alone.
// Returned evidence contains opaque location IDs, never the component values.
// CLI/source collection is deliberately separate from this provider adapter.
func (s *Set) VerifyComponents(ctx context.Context, typ, primaryName, value string, components *credentialset.Set, scope *credentialset.Scope, isExample bool) (Result, *ComponentEvidence) {
	if isExample {
		return Result{Status: Skipped}, nil
	}
	if ctx.Err() != nil {
		return Result{Status: Errored, Note: classifyErr(ctx.Err())}, nil
	}
	v := s.find(typ, value)
	if v == nil {
		return Result{Status: Unsupported}, nil
	}
	// A provider with no companion requirements keeps its ordinary typed check.
	if len(v.extractRes) == 0 {
		return s.VerifyLiteral(ctx, typ, value, nil, false), nil
	}
	failed := Result{Status: Errored, Verifier: v.ID, Note: "cross-file companion binding is missing, ambiguous or invalid"}
	if components == nil || primaryName == "" || value == "" {
		return failed, nil
	}
	const anchor = "prowl_primary_component"
	var fields []credentialset.Field
	primaryBound := false
	primaryField := anchor
	names := make([]string, 0, len(v.extractRes))
	for name := range v.extractRes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		aliases := literalAliases(name)
		for _, alias := range aliases {
			if alias == literalName(primaryName) {
				primaryBound = true
				primaryField = name
			}
		}
		fields = append(fields, credentialset.Field{Name: name, Aliases: aliases, Pattern: v.extractRes[name].String()})
	}
	if !primaryBound {
		fields = append(fields, credentialset.Field{Name: anchor, Aliases: []string{primaryName}, Pattern: regexp.QuoteMeta(value)})
	}
	schema, err := credentialset.NewSchema(fields)
	if err != nil {
		return failed, nil
	}
	result := failed
	var evidence *ComponentEvidence
	err = components.With(ctx, scope, schema, primaryName, value, func(values map[string]string, locations map[string][]string) error {
		if !primaryBound {
			delete(values, anchor)
		}
		result = s.VerifyLiteral(ctx, typ, value, values, false)
		evidence = &ComponentEvidence{Fields: make(map[string][]string, len(locations))}
		for name, ids := range locations {
			if name == primaryField {
				evidence.Primary = append([]string(nil), ids...)
			}
			if name == anchor && !primaryBound {
				continue
			}
			evidence.Fields[name] = append([]string(nil), ids...)
		}
		return nil
	})
	if err != nil {
		return failed, nil
	}
	return result, evidence
}
