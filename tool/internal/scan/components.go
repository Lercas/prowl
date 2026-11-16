package scan

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Lercas/prowl/tool/internal/credentialset"
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/verify"
	"gopkg.in/yaml.v3"
)

const componentMaxItems = 10000
const componentMaxBytes = 32 << 20
const componentMaxLiterals = 100000

type componentBatch struct {
	set     *credentialset.Set
	docs    map[int]*literalDocument
	scopes  map[int]*credentialset.Scope
	allowed map[int]map[int]bool
}

func (b *componentBatch) discard() {
	b.set.Close()
	clear(b.docs)
	clear(b.scopes)
	clear(b.allowed)
}

func (p *Pipeline) componentLocation(it model.Item, line, col int) string {
	id := p.itemLocationFingerprint(it, line, col)
	if p.options.ComponentLocationFingerprint != nil {
		return p.options.ComponentLocationFingerprint(id)
	}
	return id
}

// Only an explicitly selected flat configuration namespace can establish
// cross-document roles. Nested objects/tables and aliases require a relationship
// model; non-string scalar roles stay unknown instead of being silently omitted.
func flatComponentFields(ctx context.Context, it model.Item) (map[string]*string, bool) {
	text := strings.TrimPrefix(it.Text, "\uFEFF")
	fields := make(map[string]any)
	switch literalFormat(it) {
	case ".json":
		if jsonstrict.UnmarshalContext(ctx, []byte(text), &fields) != nil || fields == nil {
			return nil, false
		}
	case ".toml":
		if _, err := toml.Decode(text, &fields); err != nil {
			return nil, false
		}
	case ".yaml", ".yml":
		var doc yaml.Node
		if yaml.Unmarshal([]byte(text), &doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
			return nil, false
		}
		for i := 0; i < len(doc.Content[0].Content); i += 2 {
			key, value := doc.Content[0].Content[i], doc.Content[0].Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || value.Kind != yaml.ScalarNode {
				return nil, false
			}
			if _, duplicate := fields[key.Value]; duplicate {
				return nil, false
			}
			if value.Tag == "!!str" {
				fields[key.Value] = value.Value
			} else {
				fields[key.Value] = nil
			}
		}
	default:
		return nil, false
	}
	out := make(map[string]*string, len(fields))
	for name, v := range fields {
		if v != nil {
			k := reflect.TypeOf(v).Kind()
			if k == reflect.Map || k == reflect.Slice || k == reflect.Array {
				return nil, false
			}
		}
		if s, ok := v.(string); ok && s != "" {
			out[name] = &s
		} else {
			out[name] = nil
		}
	}
	return out, true
}

func (p *Pipeline) runComponents(ctx context.Context, input <-chan model.Item) []model.Finding {
	if p.options.Verifiers == nil {
		return []model.Finding{processingError(model.Item{}, "cross-file verification requires provider verification")}
	}
	set, _ := credentialset.New(credentialset.Limits{Observations: 100000, Bytes: componentMaxBytes})
	defer set.Close()
	batch := &componentBatch{set: set, docs: make(map[int]*literalDocument), scopes: make(map[int]*credentialset.Scope), allowed: make(map[int]map[int]bool)}
	options := p.options
	if options.LocationFingerprint == nil {
		// No filesystem state is created without --index. These keyed IDs belong
		// only to this invocation; an explicit index retains its stable namespace.
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return []model.Finding{processingError(model.Item{}, "cross-file identity could not be prepared")}
		}
		options.LocationFingerprint = func(source, path string, line, col int) string {
			mac := hmac.New(sha256.New, key)
			for _, part := range []string{"prowl:component-location:v1", source, path, fmt.Sprint(line), fmt.Sprint(col)} {
				_, _ = fmt.Fprintf(mac, "%d:%s", len(part), part)
			}
			return "hmac-component-location:v1:" + hex.EncodeToString(mac.Sum(nil))
		}
	}
	collector := New(options)
	var items []model.Item
	bytes, literals, valid := 0, 0, true
	collecting := true
	for collecting {
		select {
		case <-ctx.Done():
			valid, collecting = false, false
		case it, ok := <-input:
			if !ok {
				collecting = false
				break
			}
			if len(items) >= componentMaxItems || len(it.Text) > componentMaxBytes-bytes {
				model.Note(ctx, "cross_file_intake_limit", it.Path, true)
				valid, collecting = false, false
				break
			}
			bytes += len(it.Text)
			it.CredentialEntry = len(items) + 1
			items = append(items, it)
			if !valid {
				batch.discard()
				continue
			}
			if it.Error != nil {
				valid = false
				continue
			}
			if literalFormat(it) == "" && !componentEnv(it) {
				continue
			}
			var doc *literalDocument
			var fields map[string]*string
			flat := false
			if componentEnv(it) {
				doc, fields = envComponents(ctx, it)
				flat = doc != nil
			} else {
				doc = parseLiterals(ctx, it, false)
				if doc != nil && len(it.Text) <= 1<<20 {
					fields, flat = flatComponentFields(ctx, it)
				}
			}
			if doc != nil {
				if len(doc.values) > componentMaxLiterals-literals {
					model.Note(ctx, "cross_file_literal_limit", it.Path, true)
					valid = false
					batch.discard()
					continue
				}
				literals += len(doc.values)
				batch.docs[it.CredentialEntry] = doc
			}
			if it.CredentialScope == nil || doc == nil || doc.verificationUnsafe || len(it.Text) > 1<<20 || !flat {
				model.Note(ctx, "cross_file_literal_unavailable", it.Path, true)
				valid = false
				continue
			}
			batch.scopes[it.CredentialEntry] = it.CredentialScope
			batch.allowed[it.CredentialEntry] = make(map[int]bool)
			for name, value := range fields {
				if value == nil {
					id := collector.componentLocation(it, 1, 1)
					if set.ObserveUnknown(ctx, it.CredentialScope, name, id) != nil {
						valid = false
					}
				}
			}
			for _, v := range doc.values {
				if fields[v.name] == nil {
					continue
				}
				if doc.unsafeGroups[v.group] || v.noPassword || v.uiPassword {
					valid = false
					model.Note(ctx, "cross_file_literal_ambiguous", it.Path, true)
					continue
				}
				line, col := doc.lines.cols(v.start)
				id := collector.componentLocation(it, line, col)
				if err := set.Observe(ctx, it.CredentialScope, v.name, v.value, id); err != nil {
					model.Note(ctx, "cross_file_component_limit_or_invalid", it.Path, true)
					valid = false
					break
				}
				batch.allowed[it.CredentialEntry][v.start] = true
			}
		}
	}
	complete, _, _ := model.CoverageFrom(ctx).Snapshot()
	if set.Seal(ctx, valid && complete) != nil {
		valid = false
	}
	if !valid {
		batch.discard()
	}
	options.components = batch
	buffered := make(chan model.Item, len(items))
	for _, it := range items {
		buffered <- it
	}
	close(buffered)
	result := New(options).Run(ctx, buffered)
	if !valid {
		result = append(result, processingError(model.Item{}, "cross-file component inventory is incomplete; composite verification was not performed"))
	}
	return result
}

func (b *componentBatch) apply(ctx context.Context, set *verify.Set, doc *literalDocument, candidate verificationCandidate, path string, f *model.Finding) {
	// A non-literal/derived candidate can still use a standalone verifier, but
	// receives no context from which to guess companion credentials.
	if doc == nil || doc != b.docs[candidate.entry] {
		f.Verified, f.Rationale, f.Verification = verificationResult(set.VerifyLiteral(ctx, candidate.typ, candidate.value, nil, detect.IsExampleOrPlaceholder(candidate.value)))
		return
	}
	v := doc.locate(candidate.start, candidate.end)
	if v != nil && v.raw {
		f.Verified, f.Rationale, f.Verification = verificationResult(set.VerifyLiteral(ctx, candidate.typ, candidate.value, nil, detect.IsExampleOrPlaceholder(candidate.value)))
		return
	}
	if v == nil || v.value != candidate.value || doc.verificationUnsafe || doc.unsafeGroups[v.group] || !b.allowed[candidate.entry][v.start] {
		f.Verified, f.Rationale, f.Verification = verificationResult(verify.Result{Status: verify.Errored, Note: "structured literal could not be established"})
		return
	}
	r, evidence := set.VerifyComponents(ctx, candidate.typ, v.name, candidate.value, b.set, b.scopes[candidate.entry], detect.IsExampleOrPlaceholder(candidate.value))
	f.Verified, f.Rationale, f.Verification = verificationResult(r)
	if f.Verification != nil {
		f.Verification.Components = evidence
	}
}
