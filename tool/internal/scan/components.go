package scan

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Lercas/prowl/tool/internal/credentialset"
	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/verify"
	"gopkg.in/yaml.v3"
)

const componentMaxItems = 10000
const componentMaxBytes = 32 << 20
const componentMaxLiterals = 100000
const componentMaxNamespaceBytes = 32 << 20
const invalidComponentNamespace = "\x00invalid-component-namespace"

type componentBatch struct {
	set     *credentialset.Set
	docs    map[int]*literalDocument
	scopes  map[int]map[int]*credentialset.Scope
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

type componentNamespaceKey struct{}

func captureComponentNamespaces(ctx context.Context) bool {
	value, _ := ctx.Value(componentNamespaceKey{}).(bool)
	return value
}

// Encode segments, not dotted names: ["a.b"] and ["a", "b"] are unrelated.
func componentNamespace(path []string) string {
	segments := make([]any, len(path))
	for i, segment := range path {
		segments[i] = segment
	}
	return componentIndexedNamespace(segments)
}

// JSON numbers encode array indices; quoted numeric keys remain strings.
func componentIndexedNamespace(path []any) string {
	if len(path) == 0 {
		return ""
	}
	bytes := 0
	for _, segment := range path {
		switch value := segment.(type) {
		case string:
			bytes += len(value)
		case int:
			if value < 0 || value >= componentMaxLiterals {
				return invalidComponentNamespace
			}
			bytes += 6
		case json.Number:
			index, err := value.Int64()
			if err != nil || index < 0 || index >= componentMaxLiterals {
				return invalidComponentNamespace
			}
			bytes += 6
		default:
			return invalidComponentNamespace
		}
	}
	if len(path) > 64 || bytes > 4096 {
		return invalidComponentNamespace
	}
	raw, err := json.Marshal(path)
	if err != nil {
		return invalidComponentNamespace
	}
	return string(raw)
}

func componentChildNamespace(parent, name string) string {
	return componentAppendNamespace(parent, name)
}

func componentAppendNamespace(parent string, segment any) string {
	var path []any
	decoder := json.NewDecoder(strings.NewReader(parent))
	decoder.UseNumber()
	if parent != "" && decoder.Decode(&path) != nil {
		return invalidComponentNamespace
	}
	return componentIndexedNamespace(append(path, segment))
}

// Object namespaces match only by exact segment path within one acquisition.
// Object keys and array indices are distinct exact path segments.
// Every declared non-string role remains unknown, including container fields.
func componentFields(ctx context.Context, it model.Item) (map[string]map[string]*string, bool) {
	text := strings.TrimPrefix(it.Text, "\uFEFF")
	var fields any
	switch literalFormat(it) {
	case ".json":
		if jsonstrict.UnmarshalContext(ctx, []byte(text), &fields) != nil || fields == nil {
			return nil, false
		}
	case ".toml":
		mapping := make(map[string]any)
		if _, err := toml.Decode(text, &mapping); err != nil {
			return nil, false
		}
		fields = mapping
	case ".yaml", ".yml":
		var doc, extra yaml.Node
		decoder := yaml.NewDecoder(strings.NewReader(text))
		if decoder.Decode(&doc) != nil || len(doc.Content) != 1 || decoder.Decode(&extra) != io.EOF {
			return nil, false
		}
		var ok bool
		fields, ok = componentYAMLValue(ctx, doc.Content[0], 0)
		if !ok {
			return nil, false
		}
	default:
		return nil, false
	}
	out := make(map[string]map[string]*string)
	visits := 0
	var walk func(any, []any, int) bool
	walk = func(node any, path []any, depth int) bool {
		visits++
		if ctx.Err() != nil || depth > 64 || len(out) >= componentMaxLiterals {
			return false
		}
		if visits > componentMaxLiterals {
			return false
		}
		fields, mapping := node.(map[string]any)
		if !mapping {
			if node == nil {
				return false
			}
			array := reflect.ValueOf(node)
			if array.Kind() != reflect.Slice && array.Kind() != reflect.Array || array.Len() > componentMaxLiterals {
				return false
			}
			for i := 0; i < array.Len(); i++ {
				value := array.Index(i).Interface()
				if value == nil {
					continue
				}
				kind := reflect.TypeOf(value).Kind()
				if kind == reflect.Map || kind == reflect.Slice || kind == reflect.Array {
					if !walk(value, append(append([]any(nil), path...), i), depth+1) {
						return false
					}
				}
			}
			return true
		}
		namespace := componentIndexedNamespace(path)
		if namespace == invalidComponentNamespace {
			return false
		}
		values := make(map[string]*string, len(fields))
		out[namespace] = values
		for name, v := range fields {
			values[name] = nil
			if v != nil {
				k := reflect.TypeOf(v).Kind()
				if k == reflect.Map || k == reflect.Slice || k == reflect.Array {
					if !walk(v, append(append([]any(nil), path...), name), depth+1) {
						return false
					}
				}
				if s, ok := v.(string); ok && s != "" {
					values[name] = &s
				}
			}
		}
		return true
	}
	valid := walk(fields, nil, 0)
	return out, valid
}

func componentYAMLMapping(ctx context.Context, node *yaml.Node, depth int) (map[string]any, bool) {
	v, ok := componentYAMLValue(ctx, node, depth)
	out, mapping := v.(map[string]any)
	return out, ok && mapping
}

func componentYAMLValue(ctx context.Context, node *yaml.Node, depth int) (any, bool) {
	d := componentYAMLDecoder{ctx: ctx, active: make(map[*yaml.Node]bool)}
	return d.value(node, depth)
}

func (p *Pipeline) runComponents(ctx context.Context, input <-chan model.Item) []model.Finding {
	if p.options.Verifiers == nil {
		return []model.Finding{processingError(model.Item{}, "cross-file verification requires provider verification")}
	}
	set, _ := credentialset.New(credentialset.Limits{Observations: 100000, Bytes: componentMaxBytes})
	defer set.Close()
	batch := &componentBatch{set: set, docs: make(map[int]*literalDocument), scopes: make(map[int]map[int]*credentialset.Scope), allowed: make(map[int]map[int]bool)}
	namespaces := make(map[*credentialset.Scope]map[string]*credentialset.Scope)
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
	bytes, literals, namespaceBytes, valid := 0, 0, 0, true
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
			var fields map[string]map[string]*string
			supported := false
			if componentEnv(it) {
				var envFields map[string]*string
				doc, envFields = envComponents(ctx, it)
				fields = map[string]map[string]*string{"": envFields}
				if doc != nil {
					doc.componentNamespaces = make(map[int]string)
					for _, v := range doc.values {
						doc.componentNamespaces[v.group] = ""
					}
				}
				supported = doc != nil
			} else {
				doc = parseLiterals(context.WithValue(ctx, componentNamespaceKey{}, true), it, false)
				if doc != nil && len(it.Text) <= 1<<20 {
					fields, supported = componentFields(ctx, it)
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
			for namespace := range fields {
				namespaceBytes += len(namespace)
			}
			if doc != nil {
				for _, namespace := range doc.componentNamespaces {
					namespaceBytes += len(namespace)
				}
			}
			if namespaceBytes > componentMaxNamespaceBytes {
				model.Note(ctx, "cross_file_namespace_limit", it.Path, true)
				valid = false
				batch.discard()
				continue
			}
			if it.CredentialScope == nil || doc == nil || doc.verificationUnsafe || len(it.Text) > 1<<20 || !supported {
				model.Note(ctx, "cross_file_literal_unavailable", it.Path, true)
				valid = false
				continue
			}
			if namespaces[it.CredentialScope] == nil {
				namespaces[it.CredentialScope] = map[string]*credentialset.Scope{"": it.CredentialScope}
			}
			scopes := namespaces[it.CredentialScope]
			batch.scopes[it.CredentialEntry] = make(map[int]*credentialset.Scope)
			batch.allowed[it.CredentialEntry] = make(map[int]bool)
			for namespace, values := range fields {
				if scopes[namespace] == nil {
					if len(scopes) >= componentMaxLiterals {
						valid = false
						break
					}
					scopes[namespace] = credentialset.NewScope()
				}
				for name, value := range values {
					if value == nil {
						id := collector.componentLocation(it, 1, 1)
						if set.ObserveUnknown(ctx, scopes[namespace], name, id) != nil {
							valid = false
						}
					}
				}
			}
			for _, v := range doc.values {
				namespace, mapped := doc.componentNamespaces[v.group]
				value := fields[namespace][v.name]
				if !mapped || value == nil || v.raw {
					continue
				}
				if *value != v.value || doc.unsafeGroups[v.group] || v.noPassword || v.uiPassword {
					valid = false
					model.Note(ctx, "cross_file_literal_ambiguous", it.Path, true)
					continue
				}
				line, col := doc.lines.cols(v.start)
				id := collector.componentLocation(it, line, col)
				if err := set.Observe(ctx, scopes[namespace], v.name, v.value, id); err != nil {
					model.Note(ctx, "cross_file_component_limit_or_invalid", it.Path, true)
					valid = false
					break
				}
				batch.allowed[it.CredentialEntry][v.start] = true
				batch.scopes[it.CredentialEntry][v.group] = scopes[namespace]
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
		f.Verified, f.Rationale, f.Verification = verificationResult(set.VerifyLiteral(ctx, candidate.typ, candidate.value, nil, candidate.isExample()))
		return
	}
	v := doc.locate(candidate.start, candidate.end)
	if v != nil && v.raw {
		f.Verified, f.Rationale, f.Verification = verificationResult(set.VerifyLiteral(ctx, candidate.typ, candidate.value, nil, candidate.isExample()))
		return
	}
	if v == nil || v.value != candidate.value || doc.verificationUnsafe || doc.unsafeGroups[v.group] || !b.allowed[candidate.entry][v.start] {
		f.Verified, f.Rationale, f.Verification = verificationResult(verify.Result{Status: verify.Errored, Note: "structured literal could not be established"})
		return
	}
	r, evidence := set.VerifyComponents(ctx, candidate.typ, v.name, candidate.value, b.set, b.scopes[candidate.entry][v.group], candidate.isExample())
	f.Verified, f.Rationale, f.Verification = verificationResult(r)
	if f.Verification != nil {
		f.Verification.Components = evidence
	}
}
