package scan

// The pinned parser and group inventory materialize qualified keys. Bound that work BEFORE calling
// the parser: a small file can reuse one large containing namespace thousands of times.
func tomlQualifiedKeyBudget(tokens []tomlLiteralToken) bool {
	type frame struct {
		bytes, parts, keyBytes, keyParts int
		array, keyMode, awaiting         bool
	}
	stack := []frame{{keyMode: true}}
	work := 0
	charge := func(bytes, parts int) bool {
		work += bytes
		return bytes <= 8192 && parts <= 64 && work <= 8<<20
	}
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		f := &stack[len(stack)-1]
		if len(stack) == 1 && f.keyMode && f.keyParts == 0 && t.kind == '[' {
			if i+1 < len(tokens) && tokens[i+1].kind == '[' {
				i++
			}
			bytes, parts := 0, 0
			for i++; i < len(tokens) && tokens[i].kind != ']'; i++ {
				if tokens[i].kind == 'q' || tokens[i].kind == 'w' {
					bytes += len(tokens[i].value) + 1
					parts++
					if !charge(bytes, parts) {
						return false
					}
				}
			}
			if i+1 < len(tokens) && tokens[i+1].kind == ']' {
				i++
			}
			f.bytes, f.parts = bytes, parts
			continue
		}
		switch t.kind {
		case '\n':
			if len(stack) == 1 {
				f.keyMode, f.awaiting, f.keyBytes, f.keyParts = true, false, 0, 0
			}
		case 'q', 'w':
			if f.keyMode && !f.array {
				f.keyBytes += len(t.value) + 1
				f.keyParts++
				if !charge(f.bytes+f.keyBytes, f.parts+f.keyParts) {
					return false
				}
			} else if f.awaiting || f.array {
				if !charge(f.bytes+f.keyBytes, f.parts+f.keyParts) {
					return false
				}
				f.awaiting = false
			}
		case '=':
			f.keyMode, f.awaiting = false, true
		case '{', '[':
			bytes, parts := f.bytes+f.keyBytes, f.parts+f.keyParts
			if !charge(bytes, parts) || len(stack) >= 64 {
				return false
			}
			f.awaiting = false
			stack = append(stack, frame{bytes: bytes, parts: parts, array: t.kind == '[', keyMode: t.kind == '{'})
		case '}', ']':
			if len(stack) <= 1 {
				continue // Syntax validation belongs to the pinned parser, not this work estimate.
			}
			stack = stack[:len(stack)-1]
		case ',':
			if !f.array {
				f.keyMode, f.awaiting, f.keyBytes, f.keyParts = true, false, 0, 0
			}
		}
	}
	return true
}
