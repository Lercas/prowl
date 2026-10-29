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
	if ctx.Err() != nil {
		return false
	}
	for _, pattern := range exclude {
		if config.PathMatch(pattern, itemPath) {
			return true
		}
	}
	if int64(len(data)) > maxBytes {
		model.Note(ctx, "max_size", itemPath, true)
		return true
	}
	if depth >= maxEmbeddedPayloadDepth {
		model.Note(ctx, "embedded_depth_limit", itemPath, true)
		logx.Warn("embedded payload depth limit reached", "path", itemPath, "limit", maxEmbeddedPayloadDepth)
		return emitSourceError(ctx, ch, itemPath, errors.New("embedded payload depth limit reached"))
	}

	limits := unpack.BoundedLimits(maxBytes, maxBytes)
	stats, recognized, err := unpack.WalkFilteredContext(ctx, itemPath, data, limits, func(path string) bool {
		return excludedSourcePath(path, exclude)
	}, func(entry unpack.Entry) error {
		if !emitPayloadDepth(ctx, ch, entry.Path, entry.Data, maxBytes, exclude, meta, depth+1) {
			return ctx.Err()
		}
		return nil
	})
	if recognized {
		if stats.DepthLimited > 0 {
			model.Note(ctx, "archive_depth_limit", itemPath, true)
		}
		if stats.Oversized > 0 {
			model.Note(ctx, "archive_entry_size_limit", itemPath, true)
		}
		if err == nil && stats.Limited > 0 {
			err = errors.New("archive content omitted at extraction limits")
		}
		if err != nil && ctx.Err() == nil {
			model.Note(ctx, "archive_incomplete", itemPath, true)
			logx.Warn("archive extraction incomplete", "path", itemPath, "err", err,
				"archives", stats.Archives, "entries", stats.Entries, "emitted", stats.Emitted)
			if !emitSourceError(ctx, ch, itemPath, err) {
				return false
			}
		}
		if err == nil || ctx.Err() != nil {
			return ctx.Err() == nil
		}
		// Keep visible plaintext evidence even when an expected archive is malformed.
	}

	mailStats, mailRecognized, mailErr := mailbox.WalkFiltered(
		itemPath,
		data,
		mailbox.BoundedLimits(maxBytes),
		func(path string) bool { return excludedSourcePath(path, exclude) },
		func(part mailbox.Part) error {
			if !emitPayloadDepth(ctx, ch, part.Path, part.Data, maxBytes, exclude, meta, depth+1) {
				return ctx.Err()
			}
			return nil
		},
	)
	if mailRecognized {
		if mailStats.Skipped > 0 {
			model.Note(ctx, "mail_part_limit", itemPath, true)
		}
		if mailErr == nil && mailStats.Limited > 0 {
			mailErr = errors.New("mail content omitted at extraction limits")
		}
		if mailErr == nil {
			return ctx.Err() == nil
		}
		if ctx.Err() == nil {
			model.Note(ctx, "mail_incomplete", itemPath, true)
			logx.Warn("mail extraction incomplete", "path", itemPath, "err", mailErr,
				"messages", mailStats.Messages, "parts", mailStats.Parts, "emitted", mailStats.Emitted)
			if !emitSourceError(ctx, ch, itemPath, mailErr) {
				return false
			}
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
			model.Note(ctx, "pdf_incomplete", itemPath, true)
			logx.Warn("PDF text extraction incomplete", "path", itemPath, "err", pdfErr,
				"pages", pdfStats.Pages, "emitted", pdfStats.Emitted, "empty", pdfStats.Empty)
			if !emitSourceError(ctx, ch, itemPath, pdfErr) {
				return false
			}
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
				model.Note(ctx, "ocr_page_limit", itemPath, true)
				logx.Warn("PDF OCR page limit reached", "path", itemPath, "limit", limit, "skipped", skipped)
				if !emitSourceError(ctx, ch, itemPath, errors.New("PDF OCR page limit reached")) {
					return false
				}
				pages = pages[:limit]
			}
			for _, page := range pages {
				path := fmt.Sprintf("%s!/page-%04d.ocr.txt", itemPath, page)
				if excludedSourcePath(path, exclude) {
					continue
				}
				text, err := engine.ExtractPDFPage(ctx, data, page)
				if err != nil {
					if ctx.Err() == nil {
						model.Note(ctx, "ocr_failed", itemPath, true)
						logx.Warn("PDF OCR failed", "path", itemPath, "page", page, "err", err)
						if !emitSourceError(ctx, ch, itemPath, err) {
							return false
						}
					}
					continue
				}
				if strings.TrimSpace(text) == "" {
					continue
				}
				if !send(ctx, ch, model.Item{Text: text, Source: sourceForPath(path), Path: path, Meta: meta}) {
					return false
				}
			}
		}
		return ctx.Err() == nil
	}

	if engine := ocrEngine(ctx); engine != nil && ocr.MaybeImage(itemPath) {
		path := itemPath + "!/ocr.txt"
		if excludedSourcePath(path, exclude) {
			return true
		}
		text, err := engine.ExtractImage(ctx, data)
		if err != nil {
			if ctx.Err() == nil {
				model.Note(ctx, "ocr_failed", itemPath, true)
				logx.Warn("image OCR failed", "path", itemPath, "err", err)
				return emitSourceError(ctx, ch, itemPath, err)
			}
			return ctx.Err() == nil
		}
		if strings.TrimSpace(text) == "" {
			return true
		}
		return send(ctx, ch, model.Item{Text: text, Source: sourceForPath(path), Path: path, Meta: meta})
	}

	if officeXML(itemPath) {
		if text, ok := extractXMLText(data); ok {
			data = text
		}
	}
	text, ok := scannableText(data)
	if !ok {
		model.Note(ctx, "binary", itemPath, false)
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
