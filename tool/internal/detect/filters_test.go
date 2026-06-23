package detect

import "testing"

func TestLooksLikeIdentifierFuncCall(t *testing.T) {
	// function-call expressions are code, not password literals — must be treated as identifiers (dropped)
	for _, v := range []string{"get_auth_from_url(proxy)", "str(password)", "password.encode(", "b64encode(data)"} {
		if !looksLikeIdentifier(v) {
			t.Errorf("looksLikeIdentifier(%q) = false; a func-call value must be rejected as non-secret", v)
		}
	}
	// a real password literal (entropy, no call shape) must NOT be treated as an identifier
	for _, v := range []string{"Xy9kLm2pQr7wNv3z", "S3cr3tValue123abc", "hunter2-pass!"} {
		if looksLikeIdentifier(v) {
			t.Errorf("looksLikeIdentifier(%q) = true; a real secret-shaped value was wrongly dropped", v)
		}
	}
}

func TestUnbalancedBracketsRejected(t *testing.T) {
	// captured code fragments (unbalanced brackets) are not password literals
	for _, v := range []string{"bytes)", "password)", "headers[", "u, password)", "data]", "}value"} {
		if !looksLikeIdentifier(v) {
			t.Errorf("looksLikeIdentifier(%q) = false; an unbalanced-bracket code fragment must be rejected", v)
		}
	}
	// real password shapes (no brackets, or balanced and not a function-call shape) must survive
	for _, v := range []string{"Str0ngP@ssw0rd!", "Xy9kLm2pQr7wNv3z", "(P@ssw0rd)", "a[1]b"} {
		if looksLikeIdentifier(v) {
			t.Errorf("looksLikeIdentifier(%q) = true; a real/balanced value was wrongly dropped", v)
		}
	}
}
