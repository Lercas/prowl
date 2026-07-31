package pdftext

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestWalkExtractsPageTextAndMetadata(t *testing.T) {
	raw := makePDF(
		`aws_access_key_id = "AKIA4MNQ2RST7UVWX9YZ"`,
		`X-Api-Key prod_metadata_secret_123456789`,
	)
	var parts []Part
	stats, recognized, err := Walk("runbook.pdf", raw, BoundedLimits(1<<20), func(part Part) error {
		parts = append(parts, part)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !recognized || stats.Pages != 1 || stats.Emitted != 2 {
		t.Fatalf("recognized=%v stats=%+v parts=%+v", recognized, stats, parts)
	}
	if !partsContain(parts, "AKIA4MNQ2RST7UVWX9YZ") {
		t.Fatalf("page text missing: %+v", parts)
	}
	if !partsContain(parts, "prod_metadata_secret_123456789") {
		t.Fatalf("metadata missing: %+v", parts)
	}
}

func TestWalkHandlesEmptyAndMalformedPDF(t *testing.T) {
	empty := makePDF("", "")
	var parts []Part
	stats, recognized, err := Walk("scan.pdf", empty, BoundedLimits(1<<20), func(part Part) error {
		parts = append(parts, part)
		return nil
	})
	if err != nil || !recognized || stats.Empty != 1 || len(stats.EmptyPages) != 1 ||
		stats.EmptyPages[0] != 1 || len(parts) != 0 {
		t.Fatalf("empty PDF: recognized=%v stats=%+v parts=%+v err=%v", recognized, stats, parts, err)
	}

	_, recognized, err = Walk("broken.pdf", []byte("%PDF-1.7 broken"), BoundedLimits(1<<20), func(Part) error {
		return nil
	})
	if !recognized || err == nil {
		t.Fatalf("malformed PDF: recognized=%v err=%v", recognized, err)
	}
	if _, recognized, err = Walk("plain.txt", []byte("plain"), BoundedLimits(1<<20), func(Part) error {
		return nil
	}); recognized || err != nil {
		t.Fatalf("plain text: recognized=%v err=%v", recognized, err)
	}
}

func TestWalkEnforcesTextLimits(t *testing.T) {
	raw := makePDF(strings.Repeat("A", 200), "")
	var parts []Part
	stats, _, err := Walk("large.pdf", raw, Limits{
		MaxPage: 32, MaxTotal: 64, MaxPages: 10,
	}, func(part Part) error {
		parts = append(parts, part)
		return nil
	})
	if err == nil || stats.Skipped != 1 || len(parts) != 0 {
		t.Fatalf("stats=%+v parts=%+v err=%v", stats, parts, err)
	}
}

func TestWalkStopsWhenConsumerReturnsError(t *testing.T) {
	want := errors.New("consumer stopped")
	calls := 0
	_, recognized, err := Walk("report.pdf", makePDF("visible text", ""), BoundedLimits(1<<20), func(Part) error {
		calls++
		return want
	})
	if !recognized || !errors.Is(err, want) || calls != 1 {
		t.Fatalf("recognized=%v calls=%d err=%v", recognized, calls, err)
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

func makePDF(pageText, subject string) []byte {
	content := "BT /F1 12 Tf 72 720 Td (" + escapePDFString(pageText) + ") Tj ET"
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] " +
			"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
		"<< /Subject (" + escapePDFString(subject) + ") >>",
	}

	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, object := range objects {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n", len(objects)+1)
	out.WriteString("0000000000 65535 f \n")
	for i := 1; i < len(offsets); i++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(
		&out,
		"trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1,
		xref,
	)
	return out.Bytes()
}

func escapePDFString(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`, "\r", `\r`, "\n", `\n`)
	return replacer.Replace(value)
}
