// Package pdftext extracts bounded text-layer content and metadata from PDF documents.
package pdftext

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"

	pdf "github.com/ledongthuc/pdf"
)

const defaultMaxPages = 10_000

// Limits bounds one PDF extraction.
type Limits struct {
	MaxPage  int64
	MaxTotal int64
	MaxPages int
}

// Part is one metadata block or page of extracted text.
type Part struct {
	Path string
	Data []byte
}

// Stats summarizes a PDF extraction.
type Stats struct {
	Pages      int
	Emitted    int
	Empty      int
	Skipped    int
	EmptyPages []int
}

type extractor struct {
	limits    Limits
	remaining uint64
	stats     Stats
	emit      func(Part) error
}

// BoundedLimits derives conservative PDF limits from the scan's per-file cap.
func BoundedLimits(maxPage int64) Limits {
	if maxPage <= 0 {
		maxPage = 10 << 20
	}
	maxTotal := maxPage
	if maxPage <= math.MaxInt64/4 {
		maxTotal = maxPage * 4
	}
	if maxTotal > 512<<20 {
		maxTotal = 512 << 20
	}
	if maxTotal < maxPage {
		maxTotal = maxPage
	}
	return Limits{MaxPage: maxPage, MaxTotal: maxTotal, MaxPages: defaultMaxPages}
}

// MaybeDocument reports whether name or magic bytes identify a PDF.
func MaybeDocument(name string, raw []byte) bool {
	return strings.HasSuffix(strings.ToLower(name), ".pdf") || bytes.HasPrefix(raw, []byte("%PDF-"))
}

// Walk extracts PDF metadata and each available text-layer page. It does not perform OCR.
// recognized=false means the payload is not a PDF by extension or magic bytes.
func Walk(root string, raw []byte, limits Limits, emit func(Part) error) (stats Stats, recognized bool, err error) {
	if !MaybeDocument(root, raw) {
		return stats, false, nil
	}
	recognized = true
	limits = normalizeLimits(limits)
	if limits.MaxPage == math.MaxInt64 {
		return stats, true, errors.New("PDF page size limit is too large")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("PDF parser panic recovered: %v", recovered)
		}
	}()
	if len(raw) < 100 {
		return stats, true, errors.New("PDF is too short")
	}
	reader, err := pdf.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return stats, true, err
	}
	x := &extractor{
		limits: limits,
		// normalizeLimits guarantees a positive int64 total before this conversion.
		remaining: uint64(limits.MaxTotal), //nolint:gosec
		emit:      emit,
	}

	var extractionErrors []error
	if metadata, metadataErr := documentMetadata(reader); metadataErr != nil {
		extractionErrors = append(extractionErrors, fmt.Errorf("metadata: %w", metadataErr))
	} else if metadata != "" {
		if outputErr := x.output(root+"!/metadata.txt", metadata); outputErr != nil {
			if !errors.Is(outputErr, errPageLimit) && !errors.Is(outputErr, errTotalLimit) {
				return x.stats, true, outputErr
			}
			extractionErrors = append(extractionErrors, outputErr)
		}
	}

	pages := reader.NumPage()
	x.stats.Pages = pages
	if pages < 0 {
		return x.stats, true, errors.New("PDF has a negative page count")
	}
	toProcess := pages
	if toProcess > limits.MaxPages {
		toProcess = limits.MaxPages
		x.stats.Skipped += pages - toProcess
		extractionErrors = append(extractionErrors, fmt.Errorf("PDF exceeds the %d-page limit", limits.MaxPages))
	}
	for pageNumber := 1; pageNumber <= toProcess; pageNumber++ {
		text, pageErr := pageText(reader, pageNumber)
		if pageErr != nil {
			x.stats.Skipped++
			extractionErrors = append(extractionErrors, fmt.Errorf("page %d: %w", pageNumber, pageErr))
			continue
		}
		if strings.TrimSpace(text) == "" {
			x.stats.Empty++
			x.stats.EmptyPages = append(x.stats.EmptyPages, pageNumber)
			continue
		}
		pagePath := fmt.Sprintf("%s!/page-%04d.txt", root, pageNumber)
		if outputErr := x.output(pagePath, text); outputErr != nil {
			x.stats.Skipped++
			extractionErrors = append(extractionErrors, fmt.Errorf("page %d: %w", pageNumber, outputErr))
			if errors.Is(outputErr, errTotalLimit) {
				break
			}
			if !errors.Is(outputErr, errPageLimit) {
				return x.stats, true, errors.Join(extractionErrors...)
			}
		}
	}
	return x.stats, true, errors.Join(extractionErrors...)
}

var (
	errPageLimit  = errors.New("PDF per-page text limit exceeded")
	errTotalLimit = errors.New("PDF cumulative text limit exceeded")
)

func normalizeLimits(l Limits) Limits {
	if l.MaxPage <= 0 {
		l.MaxPage = 10 << 20
	}
	if l.MaxTotal <= 0 {
		if l.MaxPage > math.MaxInt64/4 {
			l.MaxTotal = math.MaxInt64
		} else {
			l.MaxTotal = l.MaxPage * 4
		}
	}
	if l.MaxPages <= 0 {
		l.MaxPages = defaultMaxPages
	}
	return l
}

func (x *extractor) output(name, text string) error {
	data := bytes.TrimSpace([]byte(text))
	if len(data) == 0 {
		return nil
	}
	if int64(len(data)) > x.limits.MaxPage {
		return fmt.Errorf("%w (%d bytes)", errPageLimit, x.limits.MaxPage)
	}
	if uint64(len(data)) > x.remaining {
		return fmt.Errorf("%w (%d bytes)", errTotalLimit, x.limits.MaxTotal)
	}
	x.remaining -= uint64(len(data))
	if err := x.emit(Part{Path: name, Data: data}); err != nil {
		return err
	}
	x.stats.Emitted++
	return nil
}

func pageText(reader *pdf.Reader, pageNumber int) (text string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			text = ""
			err = fmt.Errorf("parser panic recovered: %v", recovered)
		}
	}()
	return reader.Page(pageNumber).GetPlainText(nil)
}

func documentMetadata(reader *pdf.Reader) (text string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			text = ""
			err = fmt.Errorf("parser panic recovered: %v", recovered)
		}
	}()
	info := reader.Trailer().Key("Info")
	var out strings.Builder
	for _, key := range []string{"Title", "Author", "Subject", "Keywords", "Creator", "Producer"} {
		value := strings.TrimSpace(info.Key(key).Text())
		if value == "" {
			continue
		}
		out.WriteString(key)
		out.WriteString(": ")
		out.WriteString(value)
		out.WriteByte('\n')
	}
	return strings.TrimSpace(out.String()), nil
}
