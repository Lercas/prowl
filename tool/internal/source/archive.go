package source

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/mailbox"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/ocr"
	"github.com/Lercas/prowl/tool/internal/pdftext"
	"github.com/Lercas/prowl/tool/internal/unpack"
)

const maxEmbeddedPayloadDepth = 8

// skipByExtension keeps binary/media formats out of the text scanner while allowing archive, Office,
// and PDF extensions through to bounded in-memory extractors. Mail exports are ordinary text from the
// extension filter's perspective and are recognized later by emitPayload.
func skipByExtension(ctx context.Context, path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if engine := ocrEngine(ctx); engine != nil && ocr.MaybeImage(path) {
		return false
	}
	return skipExt[ext] && !unpack.MaybeArchive(path) && !pdftext.MaybeDocument(path, nil)
}

// emitPayload sends one normal text file, or recursively expands a supported archive/mail export and
// sends its scannable members. meta is copied by reference but treated read-only by the scan pipeline.
func emitPayload(ctx context.Context, ch chan<- model.Item, itemPath string, data []byte, maxBytes int64, exclude []string, meta map[string]any) bool {
	return emitPayloadDepth(ctx, ch, itemPath, data, maxBytes, exclude, meta, 0)
}

func emitPayloadDepth(ctx context.Context, ch chan<- model.Item, itemPath string, data []byte, maxBytes int64, exclude []string, meta map[string]any, depth int) bool {
	for _, pattern := range exclude {
		if config.PathMatch(pattern, itemPath) {
			return true
		}
	}
	if depth >= maxEmbeddedPayloadDepth {
		logx.Warn("embedded payload depth limit reached", "path", itemPath, "limit", maxEmbeddedPayloadDepth)
		return true
	}

	limits := unpack.BoundedLimits(maxBytes, maxBytes)
	stats, recognized, err := unpack.Walk(itemPath, data, limits, func(entry unpack.Entry) error {
		if !emitPayloadDepth(ctx, ch, entry.Path, entry.Data, maxBytes, exclude, meta, depth+1) {
			return ctx.Err()
		}
		return nil
	})
	if recognized {
		if err != nil && ctx.Err() == nil {
			logx.Warn("archive extraction incomplete", "path", itemPath, "err", err,
				"archives", stats.Archives, "entries", stats.Entries, "emitted", stats.Emitted)
		}
		return ctx.Err() == nil
	}

	mailStats, mailRecognized, mailErr := mailbox.Walk(
		itemPath,
		data,
		mailbox.BoundedLimits(maxBytes),
		func(part mailbox.Part) error {
			if !emitPayloadDepth(ctx, ch, part.Path, part.Data, maxBytes, exclude, meta, depth+1) {
				return ctx.Err()
			}
			return nil
		},
	)
	if mailRecognized {
		if mailErr == nil {
			return ctx.Err() == nil
		}
		if ctx.Err() == nil {
			logx.Warn("mail extraction incomplete", "path", itemPath, "err", mailErr,
				"messages", mailStats.Messages, "parts", mailStats.Parts, "emitted", mailStats.Emitted)
		}
		// A malformed EML/MBOX is still text. Fall through and scan its raw representation so a
		// parser error cannot hide an otherwise visible credential.
	}

	pdfStats, pdfRecognized, pdfErr := pdftext.Walk(
		itemPath,
		data,
		pdftext.BoundedLimits(maxBytes),
		func(part pdftext.Part) error {
			if !emitPayloadDepth(ctx, ch, part.Path, part.Data, maxBytes, exclude, meta, depth+1) {
				return ctx.Err()
			}
			return nil
		},
	)
	if pdfRecognized {
		if pdfErr != nil && ctx.Err() == nil {
			logx.Warn("PDF text extraction incomplete", "path", itemPath, "err", pdfErr,
				"pages", pdfStats.Pages, "emitted", pdfStats.Emitted, "empty", pdfStats.Empty)
		}
		if engine := ocrEngine(ctx); engine != nil && ctx.Err() == nil {
			pages := pdfStats.EmptyPages
			if engine.AllPDFPages() {
				pages = make([]int, pdfStats.Pages)
				for i := range pages {
					pages[i] = i + 1
				}
			}
			if limit := engine.MaxPDFPages(); len(pages) > limit {
				skipped := len(pages) - limit
				engine.Skip(skipped, fmt.Sprintf("PDF OCR page limit reached for %s", itemPath))
				logx.Warn("PDF OCR page limit reached", "path", itemPath, "limit", limit, "skipped", skipped)
				pages = pages[:limit]
			}
			for _, page := range pages {
				text, err := engine.ExtractPDFPage(ctx, data, page)
				if err != nil {
					if ctx.Err() == nil {
						logx.Warn("PDF OCR failed", "path", itemPath, "page", page, "err", err)
					}
					continue
				}
				if strings.TrimSpace(text) == "" {
					continue
				}
				path := fmt.Sprintf("%s!/page-%04d.ocr.txt", itemPath, page)
				if !send(ctx, ch, model.Item{Text: text, Source: sourceForPath(path), Path: path, Meta: meta}) {
					return false
				}
			}
		}
		return ctx.Err() == nil
	}

	if engine := ocrEngine(ctx); engine != nil && ocr.MaybeImage(itemPath) {
		text, err := engine.ExtractImage(ctx, data)
		if err != nil {
			if ctx.Err() == nil {
				logx.Warn("image OCR failed", "path", itemPath, "err", err)
			}
			return ctx.Err() == nil
		}
		if strings.TrimSpace(text) == "" {
			return true
		}
		path := itemPath + "!/ocr.txt"
		return send(ctx, ch, model.Item{Text: text, Source: sourceForPath(path), Path: path, Meta: meta})
	}

	if officeXML(itemPath) {
		if text, ok := extractXMLText(data); ok {
			data = text
		}
	}
	text, ok := scannableText(data)
	if !ok {
		logx.Debug("skipped: binary file", "path", itemPath)
		return true
	}
	return send(ctx, ch, model.Item{Text: string(text), Source: sourceForPath(itemPath), Path: itemPath, Meta: meta})
}

func officeXML(path string) bool {
	lower := strings.ToLower(path)
	if !strings.HasSuffix(lower, ".xml") {
		return false
	}
	return strings.Contains(lower, ".docx!/") ||
		strings.Contains(lower, ".xlsx!/") ||
		strings.Contains(lower, ".pptx!/")
}

// extractXMLText joins Office XML character data while preserving paragraph/cell boundaries. Office
// applications may split one token across adjacent text runs; parsing and joining the runs recovers a
// secret that a raw XML regex would miss.
func extractXMLText(raw []byte) ([]byte, bool) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	var out strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, false
		}
		switch t := tok.(type) {
		case xml.CharData:
			s := string(t)
			if strings.TrimSpace(s) != "" {
				out.WriteString(s)
			}
		case xml.EndElement:
			switch strings.ToLower(t.Name.Local) {
			case "p", "row", "si", "c", "comment", "property":
				out.WriteByte('\n')
			}
		}
	}
	text := strings.TrimSpace(out.String())
	if text == "" {
		return nil, false
	}
	return []byte(text), true
}
