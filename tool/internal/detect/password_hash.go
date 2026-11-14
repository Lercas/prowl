package detect

// isBcryptHash recognizes the complete encoded bcrypt value, not a marker
// elsewhere on the line. Password hashes are already excluded from entropy
// candidates; they must not be reclassified as plaintext generic passwords.
// Typed provider credentials and non-hash passwords keep their normal paths.
func isBcryptHash(value string) bool {
	if len(value) != 60 || value[0] != '$' || value[1] != '2' ||
		(value[2] != 'a' && value[2] != 'b' && value[2] != 'y') ||
		value[3] != '$' || value[6] != '$' ||
		value[4] < '0' || value[4] > '9' || value[5] < '0' || value[5] > '9' {
		return false
	}
	cost := int(value[4]-'0')*10 + int(value[5]-'0')
	if cost < 4 || cost > 31 {
		return false
	}
	for i := 7; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '/') {
			return false
		}
	}
	return true
}
