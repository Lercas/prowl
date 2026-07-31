package mailbox

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func collect(t *testing.T, name, raw string, limits Limits) ([]Part, Stats, error) {
	t.Helper()
	var parts []Part
	stats, recognized, err := Walk(name, []byte(raw), limits, func(part Part) error {
		parts = append(parts, part)
		return nil
	})
	if !recognized {
		t.Fatalf("%s was not recognized", name)
	}
	return parts, stats, err
}

func TestWalkEMLDecodesBodiesAndAttachmentNames(t *testing.T) {
	secret := `aws_access_key_id = "AKIA4MNQ2RST7UVWX9YZ"`
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	raw := "From: sender@example.com\r\n" +
		"To: ops@example.com\r\n" +
		"Subject: =?UTF-8?Q?Deployment?=\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
		"--outer\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		encoded + "\r\n" +
		"--outer\r\nContent-Type: application/octet-stream; name=\"../prod.env\"\r\n" +
		"Content-Disposition: attachment; filename=\"../prod.env\"\r\n\r\n" +
		"password = SuperStrongMailPass123!\r\n--outer--\r\n"

	parts, stats, err := collect(t, "incident.eml", raw, BoundedLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Messages != 1 || stats.Emitted != 5 {
		t.Fatalf("stats = %+v, parts = %+v", stats, parts)
	}
	var joined strings.Builder
	for _, part := range parts {
		joined.Write(part.Data)
		joined.WriteByte('\n')
		if strings.Contains(part.Path, "..") {
			t.Fatalf("unsafe virtual path: %q", part.Path)
		}
	}
	if !strings.Contains(joined.String(), secret) {
		t.Fatalf("base64 body was not decoded: %+v", parts)
	}
	if !strings.Contains(joined.String(), "SuperStrongMailPass123!") {
		t.Fatalf("attachment was not emitted: %+v", parts)
	}
}

func TestWalkMBOXAndQuotedPrintable(t *testing.T) {
	message := func(sender, body string) string {
		return fmt.Sprintf(
			"From %s Sat Jan 01 00:00:00 2026\nFrom: %s\nContent-Type: text/plain\nContent-Transfer-Encoding: quoted-printable\n\n%s\n",
			sender, sender, body,
		)
	}
	raw := message("one@example.com", "clean") +
		message("two@example.com", "aws_access_key_id =3D \"AKIA4MNQ2RST7UVWX9YZ\"")
	parts, stats, err := collect(t, "mailbox.mbox", raw, BoundedLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Messages != 2 {
		t.Fatalf("messages = %d, want 2; parts = %+v", stats.Messages, parts)
	}
	found := false
	for _, part := range parts {
		if strings.Contains(string(part.Data), "AKIA4MNQ2RST7UVWX9YZ") {
			found = true
		}
	}
	if !found {
		t.Fatalf("quoted-printable MBOX body was not decoded: %+v", parts)
	}
}

func TestWalkNestedMessageAndEMLX(t *testing.T) {
	nested := "From: inner@example.com\r\nContent-Type: text/plain\r\n\r\npassword = InnerMailPass123!"
	outer := "From: outer@example.com\r\nContent-Type: message/rfc822\r\n\r\n" + nested
	parts, stats, err := collect(t, "forward.eml", outer, BoundedLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Messages != 2 {
		t.Fatalf("nested message stats = %+v", stats)
	}
	if !partsContain(parts, "InnerMailPass123!") {
		t.Fatalf("nested message body missing: %+v", parts)
	}

	emlx := fmt.Sprintf("%d\n%s\n<?xml plist>", len(nested), nested)
	parts, _, err = collect(t, "apple.emlx", emlx, BoundedLimits(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if !partsContain(parts, "InnerMailPass123!") {
		t.Fatalf("EMLX body missing: %+v", parts)
	}
}

func TestWalkDecodesLegacyTextCharset(t *testing.T) {
	raw := append(
		[]byte("From: sender@example.com\r\nContent-Type: text/plain; charset=windows-1251\r\n\r\n"),
		[]byte{0xcf, 0xe0, 0xf0, 0xee, 0xeb, 0xfc, ':', ' ', 'M', 'a', 'i', 'l', 'P', 'a', 's', 's', '1', '2', '3', '!'}...,
	)
	var parts []Part
	_, recognized, err := Walk("legacy.eml", raw, BoundedLimits(1<<20), func(part Part) error {
		parts = append(parts, part)
		return nil
	})
	if err != nil || !recognized {
		t.Fatalf("recognized=%v err=%v", recognized, err)
	}
	if !partsContain(parts, "Пароль: MailPass123!") {
		t.Fatalf("windows-1251 body was not converted to UTF-8: %+v", parts)
	}
}

func TestWalkLimitsAndNonMail(t *testing.T) {
	raw := "From: a@example.com\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("x", 100)
	parts, stats, err := collect(t, "large.eml", raw, Limits{
		MaxPart: 80, MaxTotal: 160, MaxParts: 10, MaxDepth: 4,
	})
	if err == nil {
		t.Fatal("oversized part should return an error")
	}
	if len(parts) != 1 || stats.Skipped != 1 || strings.Contains(string(parts[0].Data), strings.Repeat("x", 10)) {
		t.Fatalf("parts = %+v, stats = %+v", parts, stats)
	}
	if _, recognized, err := Walk("plain.txt", []byte(raw), BoundedLimits(1<<20), func(Part) error {
		return nil
	}); recognized || err != nil {
		t.Fatalf("plain file: recognized=%v err=%v", recognized, err)
	}

	multipartRaw := "From: a@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n" +
		"--x\r\nContent-Type: text/plain\r\n\r\none\r\n" +
		"--x\r\nContent-Type: text/plain\r\n\r\ntwo\r\n--x--\r\n"
	_, stats, err = collect(t, "parts.eml", multipartRaw, Limits{
		MaxPart: 1 << 20, MaxTotal: 2 << 20, MaxParts: 1, MaxDepth: 4,
	})
	if err == nil || stats.Parts != 2 {
		t.Fatalf("part limit: stats=%+v err=%v", stats, err)
	}
}

func partsContain(parts []Part, needle string) bool {
	for _, part := range parts {
		if strings.Contains(string(part.Data), needle) {
			return true
		}
	}
	return false
}
