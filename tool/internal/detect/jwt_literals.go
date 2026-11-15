package detect

import (
	"context"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const maxJWTEscapedScalars = 256

type jwtString struct {
	start, end  int
	name, value string
	escaped     bool
}

// Stream string tokens without collapsing duplicate members. Original lexical
// ranges remain authoritative even when escapes change the logical value length.
func jwtStrings(ctx context.Context, text string) ([]jwtString, bool) {
	type frame struct {
		object, key bool
		name        string
		escapedName bool
	}
	var stack []frame
	var values []jwtString
	d := json.NewDecoder(strings.NewReader(text))
	d.UseNumber()
	consume := func() {
		if len(stack) > 0 && stack[len(stack)-1].object {
			f := &stack[len(stack)-1]
			f.key = true
			f.name = ""
			f.escapedName = false
		}
	}
	for count := 0; ; count++ {
		if ctx.Err() != nil || count >= 4096 {
			return values, true
		}
		before := int(d.InputOffset())
		token, err := d.Token()
		if err == io.EOF {
			return values, false
		}
		if err != nil {
			return values, true
		}
		switch value := token.(type) {
		case json.Delim:
			if value == '{' || value == '[' {
				consume()
				if len(stack) >= 64 {
					return values, true
				}
				stack = append(stack, frame{object: value == '{', key: value == '{'})
			} else {
				stack = stack[:len(stack)-1]
			}
		case string:
			end := int(d.InputOffset()) - 1
			start := before
			for start < end && text[start] != '"' {
				start++
			}
			start++
			v := jwtString{start: start, end: end, value: value, escaped: strings.Contains(text[start:end], "\\")}
			if len(stack) > 0 {
				f := &stack[len(stack)-1]
				if f.object && f.key {
					f.name, f.escapedName, f.key = value, v.escaped, false
					values = append(values, v)
					continue
				}
				v.name = f.name
				v.escaped = v.escaped || f.escapedName
			}
			values = append(values, v)
			consume()
		default:
			consume()
		}
	}
}

// The raw JSON spelling of an escaped scalar is not its credential value.
// Replace those candidates with scans/nominations over complete decoded strings.
func (d *Detector) jwtEscapedFindings(ctx context.Context, text string, inner ScanResult, opts ScanOptions, rawScan ...func() ScanResult) ScanResult {
	if !strings.Contains(text, "\\") {
		if len(rawScan) > 0 {
			return rawScan[0]()
		}
		return inner
	}
	values, limited := jwtStrings(ctx, text)
	parseLimited := limited
	var selected []jwtString
	for _, v := range values {
		if limited || v.escaped {
			selected = append(selected, v)
		}
	}
	var kept []Match
	for _, v := range selected {
		if ctx.Err() != nil {
			limited = true
			break
		}
		if opts.jwtBudget.escaped >= maxJWTEscapedScalars || len(v.value) > 4096 {
			limited = true
			continue
		}
		opts.jwtBudget.escaped++
		localOptions := opts
		if opts.jwtOrigin != nil || opts.ObserveJWTPayload != nil {
			localOptions.jwtOrigin = jwtScalarOrigin(opts.jwtOrigin, text, v)
		}
		local := d.ScanWithStatus(ctx, v.value, localOptions)
		limited = limited || local.CandidateLimited || local.Base64Limited
		var nominated []Match
		if IsSecretBindingName(v.name) {
			nominated, _ = d.scalarMatches(ctx, v.value, nil, map[int]PasswordScalar{0: {Name: v.name, Value: v.value, End: len(v.value)}})
			if len(nominated) == 0 && d.genericKey {
				ok, hexOnly := nameIsSecretLike(v.name)
				if ok && namedKeyValueOK(v.value, hexOnly) {
					nominated = append(nominated, Match{Type: "generic_api_key", Value: v.value, Start: 0, End: len(v.value), Confidence: .6, Category: d.genericKeyCat, Stage: stageContextKey, ContextName: v.name})
				}
			}
		}
		if len(nominated) > 0 {
			typed := false
			for _, m := range local.Matches {
				typed = typed || m.JWTPayload || !taxonomy.GenericLast[m.Type]
			}
			if !typed {
				local.Matches = nominated
			}
		}
		for _, m := range local.Matches {
			if len(kept) >= maxScanMatches {
				limited = true
				break
			}
			if m.DecodedText == "" {
				m.DecodedText, m.DecodedStart = v.value, m.Start
				if m.ContextName == "" {
					m.ContextName = BindingName(v.value, m.Start)
				}
				if m.ContextName == "" {
					m.ContextName = v.name
				}
			}
			if m.Start == 0 && m.End == len(v.value) {
				m.LiteralContext = true
			}
			m.Start, m.End = v.start, v.end
			if m.JWTPayload {
				m.jwtContainer = Base64Span{v.start, v.end}
			}
			for i := range m.DecodeSpans {
				m.DecodeSpans[i] = Base64Span{v.start, v.end}
			}
			for i := range m.DecodeSteps {
				m.DecodeSteps[i].Start, m.DecodeSteps[i].End = v.start, v.end
			}
			kept = append(kept, m)
		}
	}
	// Logical escaped scalars own their containers before the raw normalization
	// route can cache them. Filter the raw spelling without rescanning those keys.
	if len(rawScan) > 0 {
		inner = rawScan[0]()
	}
	var ordinary []Match
	if !parseLimited {
		for _, m := range inner.Matches {
			i := sort.Search(len(selected), func(i int) bool { return selected[i].end > m.Start })
			if i == len(selected) || selected[i].start >= m.End {
				ordinary = append(ordinary, m)
			}
		}
	}
	if len(ordinary)+len(kept) > maxScanMatches {
		limited = true
		kept = kept[:min(len(kept), maxScanMatches-len(ordinary))]
	}
	kept = append(ordinary, kept...)

	inner.Matches = kept
	inner.CandidateLimited = inner.CandidateLimited || limited
	inner.Base64Limited = inner.Base64Limited || limited
	return inner
}
