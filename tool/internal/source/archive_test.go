package source

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func writeZIPFile(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	data := makeZIP(t, files)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func makeZIP(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func archiveItems(ch <-chan model.Item) []model.Item {
	var out []model.Item
	for item := range ch {
		out = append(out, item)
	}
	return out
}

func TestExtractionErrorsAreNotClean(t *testing.T) {
	for name, raw := range map[string][]byte{
		"broken.zip":   {'P', 'K', 3, 4},
		"no-magic.zip": []byte("damaged archive"),
		"empty.zip":    nil,
		"broken.gz":    []byte("damaged archive"),
		"broken.docx":  []byte("damaged document"),
		"broken.pdf":   []byte("%PDF-1.4\nmalformed PDF"),
		"broken.eml":   []byte("malformed headers\n" + encSecret),
	} {
		t.Run(name, func(t *testing.T) {
			ch := make(chan model.Item, 8)
			if !emitPayload(context.Background(), ch, name, raw, 1024, nil, nil) {
				t.Fatal("extraction unexpectedly cancelled")
			}
			close(ch)
			items := archiveItems(ch)
			failure := false
			fallback := false
			for _, item := range items {
				failure = failure || item.Error != nil
				fallback = fallback || strings.Contains(item.Text, encSecret)
			}
			if !failure || (name == "broken.eml" && !fallback) {
				t.Fatalf("extraction error or raw-mail fallback missing: %+v", items)
			}
		})
	}
}

func TestArchiveLimitRespectsExplicitExclusions(t *testing.T) {
	raw := makeZIP(t, map[string][]byte{
		"large.txt": bytes.Repeat([]byte("x"), 600),
		"keep.env":  []byte(encSecret),
	})
	for _, exclude := range [][]string{nil, {"large.txt"}} {
		ch := make(chan model.Item, 8)
		emitPayload(context.Background(), ch, "bundle.zip", raw, 512, exclude, nil)
		close(ch)
		items := archiveItems(ch)
		failure, kept := false, false
		for _, item := range items {
			failure = failure || item.Error != nil
			kept = kept || (item.Path == "bundle.zip!/keep.env" && item.Text == encSecret)
		}
		if !kept || failure != (len(exclude) == 0) {
			t.Fatalf("limits/exclusions misclassified coverage: exclude=%v items=%+v", exclude, items)
		}
	}
}

func TestNestedArchiveDepthIsIncomplete(t *testing.T) {
	raw := makeZIP(t, map[string][]byte{"secret.env": []byte(encSecret)})
	for i := 0; i < 3; i++ {
		raw = makeZIP(t, map[string][]byte{"inner.zip": raw})
	}
	ch := make(chan model.Item, 8)
	emitPayload(context.Background(), ch, "nested.zip", raw, 4096, nil, nil)
	close(ch)
	items := archiveItems(ch)
	if len(items) != 1 || items[0].Error == nil {
		t.Fatalf("depth-capped archive was certified clean: %+v", items)
	}
}

func TestFilesystemExpandsZIPAndHonorsInnerExclude(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "bundle.zip")
	writeZIPFile(t, archive, map[string][]byte{
		"config/prod.env": []byte(`aws_access_key_id = "AKIA4MNQ2RST7UVWX9YZ"`),
		"noise/skip.txt":  []byte(`password = "ShouldNotAppear123"`),
	})
	items := archiveItems(Filesystem(context.Background(), []string{dir}, []string{"**/skip.txt"}, 1<<20))
	if len(items) != 1 {
		t.Fatalf("items = %+v", items)
	}
	if !strings.HasSuffix(items[0].Path, "bundle.zip!/config/prod.env") ||
		!strings.Contains(items[0].Text, "AKIA4MNQ2RST7UVWX9YZ") {
		t.Fatalf("archive item = %+v", items[0])
	}
}

func TestFilesystemExtractsSplitSecretFromDOCX(t *testing.T) {
	dir := t.TempDir()
	docx := filepath.Join(dir, "runbook.docx")
	documentXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="urn:test"><w:body><w:p>
<w:r><w:t>aws_access_key_id = "AKIA4MNQ2R</w:t></w:r><w:r><w:t>ST7UVWX9YZ"</w:t></w:r>
</w:p></w:body></w:document>`)
	writeZIPFile(t, docx, map[string][]byte{
		"[Content_Types].xml": []byte(`<Types/>`),
		"word/document.xml":   documentXML,
	})
	items := archiveItems(Filesystem(context.Background(), []string{docx}, nil, 1<<20))
	var document *model.Item
	for i := range items {
		if strings.HasSuffix(items[i].Path, "word/document.xml") {
			document = &items[i]
			break
		}
	}
	if document == nil {
		t.Fatalf("document.xml not emitted: %+v", items)
	}
	if document.Source != "file" || !strings.Contains(document.Text, "AKIA4MNQ2RST7UVWX9YZ") {
		t.Fatalf("Office text was not joined correctly: %+v", document)
	}

	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	input := make(chan model.Item, 1)
	input <- *document
	close(input)
	findings := scan.Run(context.Background(), input, detect.New(tax), nil, nil, 1, nil, nil)
	found := false
	for _, finding := range findings {
		if finding.Type == "aws_access_key_id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("split DOCX secret produced no AWS finding: %+v", findings)
	}
}

func TestFilesystemSkipsArchiveBeyondCompressedMaxSize(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "large.zip")
	writeZIPFile(t, archive, map[string][]byte{"random.bin": bytes.Repeat([]byte{0x42}, 4096)})
	if items := archiveItems(Filesystem(context.Background(), []string{archive}, nil, 32)); len(items) != 1 || items[0].Error == nil {
		t.Fatalf("oversized compressed archive must emit a diagnostic: %+v", items)
	}
}

func TestFilesystemDecodesEMLAndExpandsAttachedArchive(t *testing.T) {
	dir := t.TempDir()
	attachment := makeZIP(t, map[string][]byte{
		"config/prod.env": []byte(`aws_access_key_id = "AKIA4MNQ2RST7UVWX9YZ"`),
	})
	raw := "From: deploy@example.com\r\n" +
		"To: ops@example.com\r\n" +
		"Subject: deployment bundle\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=prowl\r\n\r\n" +
		"--prowl\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
		"password =3D MailBodyPass123!\r\n" +
		"--prowl\r\nContent-Type: application/zip; name=bundle.zip\r\n" +
		"Content-Disposition: attachment; filename=bundle.zip\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(attachment) + "\r\n--prowl--\r\n"
	eml := filepath.Join(dir, "deployment.eml")
	if err := os.WriteFile(eml, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	items := archiveItems(Filesystem(context.Background(), []string{eml}, nil, 1<<20))
	var bodyFound, archiveFound bool
	for _, item := range items {
		if strings.Contains(item.Text, "MailBodyPass123!") {
			bodyFound = true
		}
		if strings.HasSuffix(item.Path, "deployment.eml!/bundle.zip!/config/prod.env") &&
			strings.Contains(item.Text, "AKIA4MNQ2RST7UVWX9YZ") {
			archiveFound = true
		}
	}
	if !bodyFound || !archiveFound {
		t.Fatalf("bodyFound=%v archiveFound=%v items=%+v", bodyFound, archiveFound, items)
	}

	filtered := archiveItems(Filesystem(context.Background(), []string{eml}, []string{"**/prod.env"}, 1<<20))
	for _, item := range filtered {
		if strings.HasSuffix(item.Path, "prod.env") {
			t.Fatalf("inner attachment path ignored --exclude: %+v", item)
		}
	}
}

func TestFilesystemDecodesMBOXMessages(t *testing.T) {
	dir := t.TempDir()
	raw := "From one@example.com Sat Jan 01 00:00:00 2026\n" +
		"From: one@example.com\nContent-Type: text/plain\n\nclean\n" +
		"From two@example.com Sat Jan 01 00:00:01 2026\n" +
		"From: two@example.com\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n" +
		base64.StdEncoding.EncodeToString([]byte(`password = "MailboxPass123!"`)) + "\n"
	mbox := filepath.Join(dir, "incident.mbox")
	if err := os.WriteFile(mbox, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	items := archiveItems(Filesystem(context.Background(), []string{mbox}, nil, 1<<20))
	found := false
	for _, item := range items {
		if strings.Contains(item.Text, "MailboxPass123!") &&
			strings.Contains(item.Path, "message-000002.eml!/body.txt") {
			found = true
		}
	}
	if !found {
		t.Fatalf("second MBOX message was not decoded: %+v", items)
	}
}

func TestFilesystemExtractsPDFTextInsideArchive(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "documents.zip")
	writeZIPFile(t, archive, map[string][]byte{
		"reports/runbook.pdf": makeTestPDF(`aws_access_key_id = "AKIA4MNQ2RST7UVWX9YZ"`),
	})

	items := archiveItems(Filesystem(context.Background(), []string{archive}, nil, 1<<20))
	var page *model.Item
	for i := range items {
		if strings.HasSuffix(items[i].Path, "documents.zip!/reports/runbook.pdf!/page-0001.txt") {
			page = &items[i]
			break
		}
	}
	if page == nil || !strings.Contains(page.Text, "AKIA4MNQ2RST7UVWX9YZ") {
		t.Fatalf("PDF page was not recursively extracted: %+v", items)
	}

	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	input := make(chan model.Item, 1)
	input <- *page
	close(input)
	findings := scan.Run(context.Background(), input, detect.New(tax), nil, nil, 1, nil, nil)
	found := false
	for _, finding := range findings {
		if finding.Type == "aws_access_key_id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("PDF secret produced no AWS finding: %+v", findings)
	}
}

func makeTestPDF(text string) []byte {
	content := "BT /F1 12 Tf 72 720 Td (" + strings.NewReplacer(
		`\`, `\\`, `(`, `\(`, `)`, `\)`, "\r", `\r`, "\n", `\n`,
	).Replace(text) + ") Tj ET"
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] " +
			"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
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
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}
