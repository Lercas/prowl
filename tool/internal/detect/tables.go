package detect

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"
)

const stageTable = "L1-context-table"
const maxTableRows = 4096
const maxTableBytes = 1 << 20
const maxTableLine = 8192
const maxTableColumns = 32

type tableCell struct{ start, end int }
type tableRow struct {
	cells          []tableCell
	start, end     int
	bordered, jira bool
	limited        bool
}
type tableField struct {
	name, kind string
	hexOnly    bool
}

// parseTableRow handles delimiter escapes, not arbitrary Markdown expressions.
// It keeps source offsets; table values are never interpreted as executable code.
func parseTableRow(text string, start, end int) (tableRow, bool) {
	row := tableRow{start: start, end: end}
	for start < end && (text[start] == ' ' || text[start] == '\t') {
		start++
	}
	for end > start && (text[end-1] == ' ' || text[end-1] == '\t' || text[end-1] == '\r') {
		end--
	}
	if start == end {
		return row, false
	}
	if end-start > maxTableLine {
		// Inspect only a bounded first label to distinguish table-shaped input
		// from long expressions containing bitwise operators.
		row.limited = true
		lo := start
		for lo < end && text[lo] == '|' {
			lo++
		}
		hi := lo
		for hi < end && hi-lo <= 128 && text[hi] != '|' {
			hi++
		}
		if hi < end && text[hi] == '|' {
			row.cells = []tableCell{{lo, hi}}
		}
		return row, false
	}
	leading := text[start] == '|'
	trailing := text[end-1] == '|' && !tableEscaped(text, start, end-1)
	row.bordered = leading && trailing
	row.jira = row.bordered && end-start >= 4 && text[start+1] == '|' && text[end-2] == '|'
	width := 1
	if row.jira {
		width = 2
	}
	if leading {
		start += width
	}
	if trailing {
		end -= width
	}
	if start > end {
		return row, false
	}
	cellStart := start
	for i := start; i < end; i++ {
		if text[i] != '|' || tableEscaped(text, start, i) {
			continue
		}
		if row.jira && (i+1 >= end || text[i+1] != '|') {
			return row, false
		}
		if len(row.cells) >= maxTableColumns {
			row.limited = true
			return row, false
		}
		row.cells = append(row.cells, tableCell{cellStart, i})
		i += width - 1
		cellStart = i + 1
	}
	if len(row.cells) == 0 || len(row.cells) >= maxTableColumns {
		row.limited = len(row.cells) >= maxTableColumns
		return row, false
	}
	row.cells = append(row.cells, tableCell{cellStart, end})
	return row, true
}

func tableEscaped(text string, lo, i int) bool {
	n := 0
	for i > lo && text[i-1] == '\\' {
		n++
		i--
	}
	return n%2 == 1
}

func renderTableCell(text string, cell tableCell) (string, int, int) {
	lo, hi := cell.start, cell.end
	for lo < hi && (text[lo] == ' ' || text[lo] == '\t') {
		lo++
	}
	for hi > lo && (text[hi-1] == ' ' || text[hi-1] == '\t') {
		hi--
	}
	// Two layers cover an inline code span around a quoted value, without
	// repeatedly stripping characters that may belong to a credential.
	for range 2 {
		raw := text[lo:hi]
		if len(raw) >= 4 && (strings.HasPrefix(raw, "**") && strings.HasSuffix(raw, "**") || strings.HasPrefix(raw, "{{") && strings.HasSuffix(raw, "}}")) {
			lo += 2
			hi -= 2
			continue
		}
		if len(raw) >= 2 && (raw[0] == '`' || raw[0] == '\'' || raw[0] == '"') && raw[len(raw)-1] == raw[0] {
			lo++
			hi--
			continue
		}
		break
	}
	return strings.ReplaceAll(text[lo:hi], `\|`, "|"), lo, hi
}

func tableFieldFor(text string, cell tableCell) tableField {
	if cell.end-cell.start > 128 {
		return tableField{}
	}
	name, _, _ := renderTableCell(text, cell)
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		return tableField{}
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' && r != '.' && r != ' ' {
			return tableField{}
		}
	}
	name = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, " ", "_"), "-", "_"))
	for _, cue := range []string{"password", "passphrase", "passwd", "pwd", "pass", "pw", "passwort", "kennwort", "contraseña", "wachtwoord", "пароль", "parola", "salasana", "senha"} {
		at := strings.Index(name, cue)
		if at < 0 || at > 0 && name[at-1] != '_' && len(cue) <= 4 {
			continue
		}
		suffix := name[at+len(cue):]
		if len(cue) <= 4 && suffix != "" && suffix[0] != '_' {
			continue
		}
		if passwordNameSuffixIsMeta(suffix) {
			return tableField{}
		}
		for _, meta := range []string{"хеш", "хэш", "длина", "политика", "подсказка", "описание"} {
			if strings.Contains(suffix, meta) {
				return tableField{}
			}
		}
		return tableField{name: name, kind: "password"}
	}
	if ok, hexOnly := nameIsSecretLike(name); ok {
		return tableField{name: name, kind: "key", hexOnly: hexOnly}
	}
	return tableField{}
}

func tableSeparator(text string, row tableRow) bool {
	for _, cell := range row.cells {
		value := strings.TrimSpace(text[cell.start:cell.end])
		value = strings.TrimPrefix(value, ":")
		value = strings.TrimSuffix(value, ":")
		if len(value) < 3 || strings.Trim(value, "-") != "" {
			return false
		}
	}
	return true
}

func (d *Detector) tableValue(text string, cell tableCell, field tableField) (Match, bool) {
	if field.kind == "" || cell.end-cell.start > maxTableLine {
		return Match{}, false
	}
	value, lo, hi := renderTableCell(text, cell)
	return d.fieldValue(value, lo, hi, field, stageTable)
}

// fieldValue validates logical credential data independently of its source syntax.
func (d *Detector) fieldValue(value string, lo, hi int, field tableField, stage string) (Match, bool) {
	if !utf8.ValidString(value) || strings.ContainsAny(value, " \t\r\n\v\f") || IsExampleOrPlaceholder(value) || IsTemplatePlaceholder(value) {
		return Match{}, false
	}
	typ, category := "generic_password", "generic"
	switch field.kind {
	case "password":
		size := utf8.RuneCountInString(value)
		if !d.genericPwd || size < 6 || size > 64 || isBcryptHash(value) || isVersionOrNumber(value) || hasJSOperator(value) || looksLikeUnicodeEscaped(value) {
			return Match{}, false
		}
	case "key":
		if !d.genericKey || utf8.RuneCountInString(value) > 200 || !namedKeyValueOK(value, field.hexOnly) {
			return Match{}, false
		}
		typ, category = "generic_api_key", d.genericKeyCat
	default:
		return Match{}, false
	}
	return Match{Type: typ, Value: value, Start: lo, End: hi, Confidence: 0.6, Category: category, Stage: stage, ContextName: field.name}, true
}

// tableSecrets recognizes vertical key/value rows and validated horizontal
// headers. A Markdown header is not data: defer a possible vertical match until
// the next line establishes whether it is followed by an alignment row.
func (d *Detector) tableSecrets(ctx context.Context, text string, budget int) ([]Match, bool) {
	if budget <= 0 || !d.genericPwd && !d.genericKey || !strings.Contains(text, "|") {
		return nil, false
	}
	var pending tableRow
	hasPending := false
	var active []tableField
	var out []Match
	rows, bytes := 0, 0
	limited := false
	emit := func(row tableRow, fields []tableField, vertical bool) {
		eligible := vertical && len(row.cells) == 2 && tableFieldFor(text, row.cells[0]).kind != ""
		for _, f := range fields {
			eligible = eligible || f.kind != ""
		}
		if !eligible {
			return
		}
		if rows >= maxTableRows || row.end-row.start > maxTableBytes-bytes {
			limited = true
			return
		}
		rows++
		bytes += row.end - row.start
		add := func(cell tableCell, field tableField) {
			if ctx.Err() != nil {
				return
			}
			if field.kind == "" {
				return
			}
			if m, ok := d.tableValue(text, cell, field); ok {
				for i := len(out) - 1; i >= 0 && out[i].Start >= row.start; i-- {
					if out[i].Start == m.Start && out[i].End == m.End && out[i].Type == m.Type {
						return
					}
				}
				if len(out) >= budget {
					limited = true
					return
				}
				out = append(out, m)
			}
		}
		if vertical && len(row.cells) == 2 {
			add(row.cells[1], tableFieldFor(text, row.cells[0]))
		}
		for i, field := range fields {
			if i < len(row.cells) {
				add(row.cells[i], field)
			}
		}
	}
	headers := func(row tableRow) []tableField {
		fields := make([]tableField, len(row.cells))
		for i, c := range row.cells {
			fields[i] = tableFieldFor(text, c)
		}
		return fields
	}
	for start := 0; start < len(text); {
		if ctx.Err() != nil || limited {
			break
		}
		end := strings.IndexByte(text[start:], '\n')
		if end < 0 {
			end = len(text)
		} else {
			end += start
		}
		row, ok := parseTableRow(text, start, end)
		start = end + 1
		if hasPending {
			if ok && len(row.cells) == len(pending.cells) && tableSeparator(text, row) {
				active = headers(pending)
				hasPending = false
				continue
			}
			emit(pending, nil, pending.bordered)
			hasPending = false
		}
		if !ok {
			if row.limited {
				for _, field := range active {
					limited = limited || field.kind != ""
				}
				for _, cell := range row.cells {
					limited = limited || tableFieldFor(text, cell).kind != ""
				}
			}
			active = nil
			continue
		}
		if row.jira {
			active = headers(row)
			continue
		}
		if tableSeparator(text, row) {
			active = nil
			continue
		}
		if active != nil && len(active) == len(row.cells) {
			emit(row, active, true)
			continue
		}
		active = nil
		pending = row
		hasPending = true
	}
	if hasPending && !limited && ctx.Err() == nil {
		emit(pending, nil, pending.bordered)
	}
	return out, limited || ctx.Err() != nil
}
