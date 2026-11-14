package detect

import (
	"context"
	"errors"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const maxCharCodeSource = 16 << 10
const maxCharCodeUnits = 4096
const maxCharCodeNumber = 128
const stageCharCode = "L1-charcode"

// Only static NumericLiterals are accepted, never identifiers or expressions.
// Separators must occur between digits; legacy leading-zero octal is ambiguous.
const decimalDigits = `[0-9](?:_?[0-9])*`

var reCharCodeNumber = regexp.MustCompile(`^[+-]?(?:0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*|0[bB][01](?:_?[01])*|0[oO][0-7](?:_?[0-7])*|(?:(?:0|[1-9](?:_?[0-9])*)(?:\.(?:` + decimalDigits + `)?)?|\.` + decimalDigits + `)(?:[eE][+-]?` + decimalDigits + `)?)$`)

// charCodeUnit implements ToUint16 for numeric literals: round to the Number
// representation, truncate towards zero, then reduce modulo 65536 (ECMA-262 7.1.9).
func charCodeUnit(raw string) (uint16, bool) {
	if len(raw) == 0 || len(raw) > maxCharCodeNumber || !reCharCodeNumber.MatchString(raw) {
		return 0, false
	}
	raw = strings.ReplaceAll(raw, "_", "")
	sign := 1.0
	if raw[0] == '-' || raw[0] == '+' {
		if raw[0] == '-' {
			sign = -1
		}
		raw = raw[1:]
	}
	var number float64
	if len(raw) > 2 && raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X' || raw[1] == 'b' || raw[1] == 'B' || raw[1] == 'o' || raw[1] == 'O') {
		base := 16
		if raw[1] == 'b' || raw[1] == 'B' {
			base = 2
		}
		if raw[1] == 'o' || raw[1] == 'O' {
			base = 8
		}
		var integer big.Int
		if _, ok := integer.SetString(raw[2:], base); !ok {
			return 0, false
		}
		number, _ = integer.Float64()
	} else {
		var err error
		number, err = strconv.ParseFloat(raw, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return 0, false
		}
	}
	number *= sign
	if math.IsInf(number, 0) || math.IsNaN(number) || number == 0 {
		return 0, true
	}
	number = math.Mod(math.Trunc(number), 65536)
	if number < 0 {
		number += 65536
	}
	return uint16(number), true // bounded by modulo above
}

type charCodeCall struct {
	start, end  int
	value       string
	brokenUTF16 bool
}

func charCodeSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// parseCharCode is a bounded grammar reader, not an evaluator. Direct calls,
// literal-array spread and apply(null/undefined, [literals]) share one reader.
func parseCharCode(ctx context.Context, text string, start int) (call charCodeCall, known, limited bool) {
	call.start = start
	if start > 0 {
		prev, _ := utf8.DecodeLastRuneInString(text[:start])
		if comparisonIdentByte(text[start-1]) || prev == '.' || unicode.IsLetter(prev) || unicode.IsDigit(prev) || unicode.IsMark(prev) || unicode.Is(unicode.Pc, prev) || prev == '\u200c' || prev == '\u200d' {
			return call, false, false
		}
	}
	end := min(len(text), start+maxCharCodeSource)
	i := start + len("String")
	ws := func() {
		for i < end && charCodeSpace(text[i]) {
			i++
		}
	}
	take := func(s string) bool {
		if !strings.HasPrefix(text[i:end], s) {
			return false
		}
		i += len(s)
		return true
	}
	ws()
	if !take(".") {
		return call, false, i == end && end < len(text)
	}
	ws()
	if !take("fromCharCode") {
		return call, false, false
	}
	if i < end && comparisonIdentByte(text[i]) {
		return call, false, false
	}
	known = true
	ws()
	apply := false
	if i < end && text[i] == '.' {
		i++
		ws()
		if !take("apply") {
			return call, false, false
		}
		apply = true
		ws()
	}
	if !take("(") {
		return call, known, i == end && end < len(text)
	}
	ws()
	array := false
	if apply {
		if !take("null") && !take("undefined") {
			return call, known, false
		}
		ws()
		if !take(",") {
			return call, known, false
		}
		ws()
		if !take("[") {
			return call, known, false
		}
		array = true
	} else if take("...") {
		ws()
		if !take("[") {
			return call, known, false
		}
		array = true
	}
	ws()
	close := byte(')')
	if array {
		close = ']'
	}
	var units []uint16
	for i < end && text[i] != close {
		if ctx.Err() != nil {
			return call, known, false
		}
		lo := i
		for i < end && !charCodeSpace(text[i]) && text[i] != ',' && text[i] != close {
			i++
			if i-lo > maxCharCodeNumber {
				return call, known, true
			}
		}
		unit, ok := charCodeUnit(text[lo:i])
		if !ok {
			return call, known, false
		}
		if len(units) >= maxCharCodeUnits {
			return call, known, true
		}
		units = append(units, unit)
		ws()
		if i >= end {
			break
		}
		if text[i] == close {
			break
		}
		if !take(",") {
			return call, known, false
		}
		ws()
	}
	if i >= end {
		return call, known, end < len(text)
	}
	i++
	if array {
		ws()
		if apply && i < end && text[i] == ',' {
			i++
			ws()
		}
		if !take(")") {
			return call, known, i == end && end < len(text)
		}
	}
	// Preserve pairs. Broken units permit only partial typed inspection, never a
	// generic credential made from lossy replacement characters.
	for n := 0; n < len(units); n++ {
		if units[n] >= 0xd800 && units[n] <= 0xdbff {
			if n+1 >= len(units) || units[n+1] < 0xdc00 || units[n+1] > 0xdfff {
				call.brokenUTF16 = true
				continue
			}
			n++
		} else if units[n] >= 0xdc00 && units[n] <= 0xdfff {
			call.brokenUTF16 = true
		}
	}
	call.end = i
	call.value = string(utf16.Decode(units))
	return call, known, call.brokenUTF16
}

var reCharCodeField = regexp.MustCompile("([\\pL_$][\\pL\\pN_.$\\-]{0,127})[\"'`\\])]{0,3}[ \\t]*(?:===|!==|==|!=|=>|:=|=|:)[ \\t]*$")
var reCharCodeReverseField = regexp.MustCompile("^" + comparisonOperator + "([\\pL_$][\\pL\\pN_.$]{0,64}(?:\\[[ \\t]*[\"'`][\\pL\\pN_\\-]{1,64}[\"'`][ \\t]*\\])?)")

func charCodeField(text string, call charCodeCall) tableField {
	next := skipBlanks(text, call.end)
	if next < len(text) && strings.ContainsRune(".+[(`", rune(text[next])) {
		return tableField{}
	}
	lo := max(0, call.start-viewContext)
	if nl := strings.LastIndexByte(text[lo:call.start], '\n'); nl >= 0 {
		lo += nl + 1
	}
	if ix := reCharCodeField.FindStringSubmatchIndex(text[lo:call.start]); ix != nil {
		ns, ne := nameStart(text, lo+ix[2]), lo+ix[3]
		before := skipBlanksBack(text, ns-1)
		if before >= 0 && text[before] == '+' {
			return tableField{}
		}
		suffix := text[ne:call.start]
		if (strings.Contains(suffix, "==") || strings.Contains(suffix, "!=")) && ns > 0 && (text[ns-1] == '\'' || text[ns-1] == '"' || text[ns-1] == '`') {
			open := skipBlanksBack(text, ns-2)
			if open < 1 || text[open] != '[' || !(comparisonIdentByte(text[open-1]) || text[open-1] == ']' || text[open-1] == ')') || ne+1 >= call.start || text[ne] != text[ns-1] || text[ne+1] != ']' {
				return tableField{}
			}
		}
		if field := comparisonField(text[ns:ne]); field.kind != "" {
			return field
		}
	}
	tail := text[call.end:min(len(text), call.end+viewContext)]
	if ix := reCharCodeReverseField.FindStringSubmatchIndex(tail); ix != nil {
		ne := skipBlanks(tail, ix[3])
		if ne < len(tail) && (comparisonIdentByte(tail[ne]) || strings.ContainsRune(".([+", rune(tail[ne]))) {
			return tableField{}
		}
		return comparisonField(tail[ix[2]:ix[3]])
	}
	return tableField{}
}

func (d *Detector) charCodeSecrets(ctx context.Context, text string, byteBudget, constructBudget int) ([]Match, bool) {
	if uint64(len(text)) > 1<<31-1 {
		return nil, true
	}
	var calls []charCodeCall
	var rewrites []rewrite
	var regions [][2]int
	attempts, decodedBytes := 0, 0
	limited := false
	for start := strings.Index(text, "String"); start >= 0; {
		if ctx.Err() != nil {
			break
		}
		call, known, cap := parseCharCode(ctx, text, start)
		limited = limited || cap
		if known {
			if attempts >= constructBudget {
				limited = true
				break
			}
			attempts++
		}
		step := len("String")
		if call.end > start {
			step = call.end - start
			if len(call.value) > byteBudget-decodedBytes {
				limited = true
				break
			}
			if call.value != "" {
				decodedBytes += len(call.value)
				calls = append(calls, call)
				rewrites = append(rewrites, rewrite{pos: start, end: call.end, repl: call.value})
				lo, hi := max(0, start-viewContext), min(len(text), call.end+viewContext)
				if nl := strings.LastIndexByte(text[lo:start], '\n'); nl >= 0 {
					lo += nl + 1
				}
				if nl := strings.IndexByte(text[call.end:hi], '\n'); nl >= 0 {
					hi = call.end + nl
				}
				regions = append(regions, [2]int{lo, hi})
			}
		}
		if limited {
			break
		}
		next := strings.Index(text[start+step:], "String")
		if next < 0 {
			break
		}
		start += step + next
	}
	v, cap := assembleView(ctx, text, rewrites, regions, byteBudget, attempts, limited)
	limited = limited || cap
	var out []Match
	if v != nil && ctx.Err() == nil {
		matches, cap := d.collect(ctx, v.text, "", "", d.keywordsPresent(strings.ToLower(v.text)), scanStructure(v.text, 32))
		limited = limited || cap
		spans := make(map[int]int, len(calls))
		for _, call := range calls {
			spans[call.start] = call.end
		}
		for _, m := range matches {
			if taxonomy.GenericLast[m.Type] || m.Confidence < .9 || m.Start < 0 || m.End <= m.Start || m.End > len(v.text) || anyIn(v.cuts, m.Start, m.Start) || anyIn(v.cuts, m.End, m.End) {
				continue
			}
			lo, hi := int(v.start[m.Start]), int(v.end[m.End-1])
			if end, ok := spans[lo]; !ok || end != hi {
				continue
			}
			m.Start, m.End, m.Confidence = lo, hi, m.Confidence*.95
			out = append(out, m)
		}
	}
	for _, call := range calls {
		if ctx.Err() != nil {
			break
		}
		if call.brokenUTF16 || strings.IndexFunc(call.value, unicode.IsControl) >= 0 || !utf8.ValidString(call.value) {
			continue
		}
		if field := charCodeField(text, call); field.kind != "" {
			if m, ok := d.fieldValue(call.value, call.start, call.end, field, stageCharCode); ok {
				m.Confidence *= .95
				out = append(out, m)
			}
		}
	}
	return out, limited
}
