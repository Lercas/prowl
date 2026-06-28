package detect

import "testing"

func TestLooksLikeRegexAuthority(t *testing.T) {
	for _, v := range []string{`//(?:(?:[a-zA-Z0-9\$\-\_@`, `//)?(?:[^@`} {
		if !looksLikeRegexAuthority(v) {
			t.Errorf("URL-parsing regex %q should be dropped", v)
		}
	}
	// real userinfo, including a password with a backslash, must NOT be dropped
	for _, v := range []string{"//admin:s3cretPass@", "//user:p4ssw0rd@", `//user:p\ssw0rd@`} {
		if looksLikeRegexAuthority(v) {
			t.Errorf("real basic-auth userinfo %q must NOT be dropped", v)
		}
	}
}

func TestFPResidualFilters(t *testing.T) {
	if !looksLikeUnicodeEscaped(`\u041e\u0434\u043d\u043e\u0440`) {
		t.Error("unicode-escaped string should be dropped")
	}
	if looksLikeUnicodeEscaped("Tr0ub4dor&3") || looksLikeUnicodeEscaped("ab12cd34ef56") {
		t.Error("a real password / no-escape value must NOT be dropped")
	}
	if !reRecaptchaSiteKey.MatchString("6Le-qlQaAAAAALAOLqTyG0SbA38x1xyvVnllcz_u") {
		t.Error("reCAPTCHA site key should match the shape")
	}
}

func TestLooksLikeCodePath(t *testing.T) {
	for _, v := range []string{"/includes/ajs/avatarpicker/Avatar", "/includes/jira/terminology/InitTerminologyHelpDialog", "module/Foo/Bar"} {
		if !looksLikeCodePath(v) {
			t.Errorf("code path %q should be dropped", v)
		}
	}
	// real secrets carry digits / base64 padding — must survive
	for _, v := range []string{"kP3/mN7q/R2vW8xY5z", "aB3/xY9z/q", "ZX9Kqp3NvR8sT2wYbZ7m", "/v2/api/Foo3"} {
		if looksLikeCodePath(v) {
			t.Errorf("real secret / digit-bearing path %q must NOT be dropped", v)
		}
	}
}

func TestHasJSOperator(t *testing.T) {
	// operators never occur in a password, so they veto a value whether quoted or not
	for _, v := range []string{"!1===z&&X", "0!==arguments", "x=>y"} {
		if !hasJSOperator(v) {
			t.Errorf("JS operator fragment %q should be dropped", v)
		}
	}
	for _, v := range []string{"Tr0ub4dor&3", "Winter2024!", "P@ssw0rd123"} {
		if hasJSOperator(v) {
			t.Errorf("real password %q must NOT match an operator", v)
		}
	}
}

func TestLooksLikeJSCode(t *testing.T) {
	// keywords + member-access; applied to UNQUOTED values only by the caller
	for _, v := range []string{"0!==arguments", "myfunction", "window.location", "t.externalUserManagement"} {
		if !looksLikeJSCode(v) {
			t.Errorf("JS keyword/member %q should be dropped (unquoted)", v)
		}
	}
	for _, v := range []string{"Tr0ub4dor&3", "Winter2024!", "correct-horse-battery"} {
		if looksLikeJSCode(v) {
			t.Errorf("real password %q must NOT be dropped", v)
		}
	}
}

func TestIsLicenseKeyShape(t *testing.T) {
	if !isLicenseKeyShape("2UQ52-GH3P8-USVVZ-JZYB4-V6TUG") {
		t.Error("5x5 license key should be dropped")
	}
	for _, v := range []string{"ZX9Kqp3NvR8sT2wYbZ7m", "sk_live_EXAMPLEnotrealvalue", "xoxb-12345-abc"} {
		if isLicenseKeyShape(v) {
			t.Errorf("real key %q must NOT match the license-key shape", v)
		}
	}
}

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
