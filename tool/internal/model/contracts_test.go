package model

import (
	"strings"
	"testing"
)

func TestFingerprintStableIdentityAndFieldSeparation(t *testing.T) {
	const raw = "AKIANAFGYOEYPXU1DSYP"
	const expected = "f1858c80898c8a0ac1d1648f613b209251cacca63b1e4873e24fa12f2c1ea0fe"
	if got := ComputeFingerprint("aws_access_key_id", "prod.env", raw); got != expected {
		t.Fatalf("baseline identity changed: %s", got)
	}
	seen := map[string]bool{expected: true}
	for _, fields := range [][3]string{
		{"another_type", "prod.env", raw},
		{"aws_access_key_id", "other.env", raw},
		{"aws_access_key_id", "prod.env", "AKIANAFGYOEYPXU2DSYP"},
		{"a|b", "c", raw}, {"a", "b|c", raw},
		{"пароль", "秘密.env", raw},
	} {
		got := ComputeFingerprint(fields[0], fields[1], fields[2])
		if len(got) != 64 || seen[got] || strings.Contains(got, raw) {
			t.Fatalf("identity collision or disclosure for %q", fields)
		}
		seen[got] = true
	}
	if ComputeFingerprint("aws_access_key_id", "prod.env", "") != "" {
		t.Fatal("missing value must not acquire a stable secret identity")
	}
}

func TestPEMRedactionContainsTypeAndDigestWithoutMaterial(t *testing.T) {
	const raw = "-----BEGIN RSA PRIVATE KEY-----\nYWJjZGVmZ2hpamtsbW5vcA==\n-----END RSA PRIVATE KEY-----"
	const expected = "RSA PRIVATE KEY [sha256:b150fdcc]"
	if got, ok := RedactKey(raw); !ok || got != expected || Redact(raw) != expected || !IsPEMKey(got) {
		t.Fatalf("unexpected PEM report identity: %q, %v", got, ok)
	}
	for _, kind := range []string{"PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK"} {
		value := "  -----BEGIN " + kind + "-----\nsecretmaterial\n"
		got, ok := RedactKey(value)
		if !ok || !strings.HasPrefix(got, kind+" [sha256:") || strings.Contains(got, "secretmaterial") || strings.Contains(got, "\n") {
			t.Fatalf("unsafe redaction for %s: %q", kind, got)
		}
	}
	if got, _ := RedactKey(raw + "\n"); got == expected {
		t.Fatal("different matched values must retain distinct report digests")
	}
	for _, value := range []string{"not a key", "-----BEGIN PUBLIC KEY-----", "prefix -----BEGIN RSA PRIVATE KEY-----"} {
		if got, ok := RedactKey(value); ok || got != "" || IsPEMKey(Redact(value)) {
			t.Fatal("non-private-key value mislabeled as PEM")
		}
	}
	if got := Redact(strings.Repeat("x", 1000)); got != "xxxx********xxxx" {
		t.Fatal("plain redaction must remain bounded")
	}
}

func TestIncompleteDiagnosticsRemainDistinguishableFromSecrets(t *testing.T) {
	for _, kind := range []string{"results_truncated", "response_truncated", "item_too_large", "source_error"} {
		if !IsIncompleteFinding(Finding{Type: kind}) {
			t.Fatalf("diagnostic %s could be suppressed as a secret", kind)
		}
	}
	for _, kind := range []string{"", "aws_access_key_id", "generic_password"} {
		if IsIncompleteFinding(Finding{Type: kind}) {
			t.Fatalf("secret %s became an incomplete diagnostic", kind)
		}
	}
}

func TestPathURIPreservesLiteralSourceIdentity(t *testing.T) {
	for _, tc := range []struct{ path, platform, want string }{
		{"/tmp/a b#c?.env", "linux", "file:///tmp/a%20b%23c%3F.env"},
		{"a:b/c.env", "linux", "a%3Ab/c.env"},
		{"./a/../b", "linux", "./a/../b"},
		{`a\b`, "linux", "a%5Cb"},
		{`C:\secrets\a b.env`, "windows", "file:///C:/secrets/a%20b.env"},
		{`\\server\share\a.env`, "windows", "file://server/share/a.env"},
		{`\\?\UNC\server\share\a.env`, "windows", "file://server/share/a.env"},
		{`\\?\C:\a.env`, "windows", "file:///C:/a.env"},
		{`relative\秘密.env`, "windows", "relative/%E7%A7%98%E5%AF%86.env"},
		{"", "linux", ""},
	} {
		if got := PathURI(tc.path, tc.platform); got != tc.want {
			t.Errorf("PathURI(%q, %q)=%q, want %q", tc.path, tc.platform, got, tc.want)
		}
	}
}
