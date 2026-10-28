// Package mailbox extracts bounded text bodies and attachments from EML and MBOX payloads.
package mailbox

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"path"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/html/charset"
)

const (
	defaultMaxParts = 10_000
	defaultMaxDepth = 16
)

// Limits bounds one mail export and every nested MIME entity.
type Limits struct {
	MaxPart  int64
	MaxTotal int64
	MaxParts int
	MaxDepth int
}

// Part is one decoded mail body, header block, or attachment.
type Part struct {
	Path string
	Data []byte
}

// Stats summarizes a mail expansion.
type Stats struct {
	Messages int
	Parts    int
	Emitted  int
	Skipped  int
	Limited  int // entities omitted due to size/depth limits
}

type walker struct {
	limits    Limits
	remaining uint64
	stats     Stats
	emit      func(Part) error
	sequence  int
	skip      func(string) bool
}

// BoundedLimits derives conservative mail limits from the scan's per-file cap.
func BoundedLimits(maxPart int64) Limits {
	if maxPart <= 0 {
		maxPart = 10 << 20
	}
	maxTotal := maxPart
	if maxPart <= math.MaxInt64/4 {
		maxTotal = maxPart * 4
	}
	if maxTotal > 512<<20 {
		maxTotal = 512 << 20
	}
	if maxTotal < maxPart {
		maxTotal = maxPart
	}
	return Limits{
		MaxPart: maxPart, MaxTotal: maxTotal, MaxParts: defaultMaxParts, MaxDepth: defaultMaxDepth,
	}
}

// MaybeMessage reports whether name denotes a supported mail export.
func MaybeMessage(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".eml") ||
		strings.HasSuffix(lower, ".emlx") ||
		strings.HasSuffix(lower, ".mbox")
}

// Walk decodes an EML/EMLX message or MBOX export and emits its headers, bodies, and attachments.
// recognized=false means the path is not a supported mail export.
func Walk(root string, raw []byte, limits Limits, emit func(Part) error) (stats Stats, recognized bool, err error) {
	return WalkFiltered(root, raw, limits, nil, emit)
}

// WalkFiltered excludes MIME entities before decoding their body and excludes emitted headers.
func WalkFiltered(root string, raw []byte, limits Limits, skip func(string) bool, emit func(Part) error) (stats Stats, recognized bool, err error) {
	if !MaybeMessage(root) {
		return stats, false, nil
	}
	limits = normalizeLimits(limits)
	if limits.MaxPart == math.MaxInt64 {
		return stats, true, errors.New("mail part size limit is too large")
	}
	w := &walker{
		limits: limits,
		// normalizeLimits guarantees a positive int64 total before this conversion.
		remaining: uint64(limits.MaxTotal), //nolint:gosec
		emit:      emit,
		skip:      skip,
	}
	switch {
	case strings.HasSuffix(strings.ToLower(root), ".mbox"):
		err = w.walkMBOX(root, raw)
	default:
		if strings.HasSuffix(strings.ToLower(root), ".emlx") {
			raw = stripEMLXLength(raw)
		}
		err = w.walkMessage(root, raw, 0)
	}
	return w.stats, true, err
}

func normalizeLimits(l Limits) Limits {
	if l.MaxPart <= 0 {
		l.MaxPart = 10 << 20
	}
	if l.MaxTotal <= 0 {
		if l.MaxPart > math.MaxInt64/4 {
			l.MaxTotal = math.MaxInt64
		} else {
			l.MaxTotal = l.MaxPart * 4
		}
	}
	if l.MaxParts <= 0 {
		l.MaxParts = defaultMaxParts
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = defaultMaxDepth
	}
	return l
}

func (w *walker) walkMBOX(root string, raw []byte) error {
	messages := splitMBOX(raw)
	if len(messages) == 0 {
		messages = [][]byte{raw}
	}
	for i, message := range messages {
		name := fmt.Sprintf("%s!/message-%06d.eml", root, i+1)
		if err := w.walkMessage(name, message, 0); err != nil {
			return fmt.Errorf("parse MBOX message %d: %w", i+1, err)
		}
	}
	return nil
}

func (w *walker) walkMessage(root string, raw []byte, depth int) error {
	if depth >= w.limits.MaxDepth {
		w.stats.Skipped++
		w.stats.Limited++
		return nil
	}
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("parse EML: %w", err)
	}
	w.stats.Messages++
	headers := textproto.MIMEHeader(message.Header)
	if data := renderHeaders(headers); len(data) > 0 {
		if err := w.output(root+"!/headers.txt", data); err != nil {
			return err
		}
	}
	return w.walkEntity(root, headers, message.Body, depth, true)
}

func (w *walker) walkEntity(root string, header textproto.MIMEHeader, body io.Reader, depth int, messageRoot bool) error {
	mediaType, params := parseMediaType(header.Get("Content-Type"))
	payloadPath := root
	if mediaType == "message/rfc822" {
		payloadPath += "!/message.eml"
	} else if messageRoot && !strings.HasPrefix(mediaType, "multipart/") {
		payloadPath += "!/body" + extensionForMediaType(mediaType)
	}
	if w.skip != nil && w.skip(payloadPath) {
		w.stats.Skipped++
		return nil
	}
	if depth >= w.limits.MaxDepth {
		w.stats.Skipped++
		w.stats.Limited++
		return nil
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return errors.New("multipart message has no boundary")
		}
		reader := multipart.NewReader(decodeTransfer(body, header.Get("Content-Transfer-Encoding")), boundary)
		for {
			part, err := reader.NextPart()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("read MIME multipart: %w", err)
			}
			w.stats.Parts++
			if w.stats.Parts > w.limits.MaxParts {
				_ = part.Close()
				return fmt.Errorf("mail exceeds the %d-part limit", w.limits.MaxParts)
			}
			partRoot := root + "!/" + w.partName(part.Header, mediaType)
			if data := renderHeaders(part.Header); len(data) > 0 {
				if err := w.output(partRoot+"!/headers.txt", data); err != nil {
					_ = part.Close()
					return err
				}
			}
			err = w.walkEntity(partRoot, part.Header, part, depth+1, false)
			closeErr := part.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}

	data, err := readBounded(decodeTransfer(body, header.Get("Content-Transfer-Encoding")), w.limits.MaxPart)
	if err != nil {
		w.stats.Skipped++
		return err
	}
	if strings.HasPrefix(mediaType, "text/") {
		data, err = decodeCharset(data, params["charset"], w.limits.MaxPart)
		if err != nil {
			w.stats.Skipped++
			return err
		}
	}
	if mediaType == "message/rfc822" {
		return w.walkMessage(root+"!/message.eml", data, depth+1)
	}
	if messageRoot {
		root += "!/body" + extensionForMediaType(mediaType)
	}
	return w.output(root, data)
}

func (w *walker) partName(header textproto.MIMEHeader, parentType string) string {
	_, dispositionParams := parseMediaType(header.Get("Content-Disposition"))
	_, contentParams := parseMediaType(header.Get("Content-Type"))
	for _, candidate := range []string{dispositionParams["filename"], contentParams["name"]} {
		if candidate = decodeHeader(candidate); candidate != "" {
			if clean := safeBase(candidate); clean != "" {
				return clean
			}
		}
	}
	w.sequence++
	mediaType, _ := parseMediaType(header.Get("Content-Type"))
	extension := extensionForMediaType(mediaType)
	if extension == ".bin" && strings.HasPrefix(parentType, "multipart/alternative") {
		extension = ".txt"
	}
	return fmt.Sprintf("part-%06d%s", w.sequence, extension)
}

func extensionForMediaType(mediaType string) string {
	switch {
	case mediaType == "message/rfc822":
		return ".eml"
	case mediaType == "text/html":
		return ".html"
	case strings.HasPrefix(mediaType, "text/"):
		return ".txt"
	default:
		return ".bin"
	}
}

func (w *walker) output(name string, data []byte) error {
	if w.skip != nil && w.skip(name) {
		w.stats.Skipped++
		return nil
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if int64(len(data)) > w.limits.MaxPart {
		w.stats.Skipped++
		w.stats.Limited++
		return nil
	}
	if uint64(len(data)) > w.remaining {
		return fmt.Errorf("mail content expands beyond the %d-byte cumulative limit", w.limits.MaxTotal)
	}
	w.remaining -= uint64(len(data))
	if err := w.emit(Part{Path: name, Data: data}); err != nil {
		return err
	}
	w.stats.Emitted++
	return nil
}

func parseMediaType(value string) (string, map[string]string) {
	if strings.TrimSpace(value) == "" {
		return "text/plain", map[string]string{}
	}
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0])), map[string]string{}
	}
	return strings.ToLower(mediaType), params
}

func decodeTransfer(body io.Reader, encoding string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		return quotedprintable.NewReader(body)
	default:
		return body
	}
}

func decodeCharset(data []byte, label string, limit int64) ([]byte, error) {
	label = strings.TrimSpace(label)
	if label == "" || strings.EqualFold(label, "utf-8") || strings.EqualFold(label, "us-ascii") {
		return data, nil
	}
	reader, err := charset.NewReaderLabel(label, bytes.NewReader(data))
	if err != nil {
		return data, nil // Preserve the original bytes when the declared charset is unknown.
	}
	return readBounded(reader, limit)
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 || limit == math.MaxInt64 {
		return nil, errors.New("invalid mail read limit")
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("mail part exceeds the %d-byte read limit", limit)
	}
	return data, nil
}

func renderHeaders(header textproto.MIMEHeader) []byte {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, key := range keys {
		for _, value := range header.Values(key) {
			out.WriteString(key)
			out.WriteString(": ")
			out.WriteString(decodeHeader(value))
			out.WriteByte('\n')
		}
	}
	return []byte(out.String())
}

func decodeHeader(value string) string {
	decoder := &mime.WordDecoder{CharsetReader: charset.NewReaderLabel}
	decoded, err := decoder.DecodeHeader(value)
	if err != nil {
		return value
	}
	return decoded
}

func safeBase(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	base := path.Base(strings.TrimSpace(name))
	if base == "" || base == "." || base == ".." {
		return ""
	}
	return base
}

func stripEMLXLength(raw []byte) []byte {
	line, rest, found := bytes.Cut(raw, []byte{'\n'})
	if !found {
		return raw
	}
	length, err := strconv.ParseInt(strings.TrimSpace(string(line)), 10, 64)
	if err != nil || length <= 0 || length > int64(len(rest)) {
		return raw
	}
	return rest[:length]
}

func splitMBOX(raw []byte) [][]byte {
	var messages [][]byte
	var start int
	haveEnvelope := false
	for lineStart := 0; lineStart < len(raw); {
		lineEnd := bytes.IndexByte(raw[lineStart:], '\n')
		if lineEnd < 0 {
			lineEnd = len(raw)
		} else {
			lineEnd += lineStart
		}
		line := bytes.TrimSuffix(raw[lineStart:lineEnd], []byte{'\r'})
		next := lineEnd
		if next < len(raw) {
			next++
		}
		if isEnvelopeLine(line) && looksLikeHeaders(raw[next:]) {
			if haveEnvelope && lineStart > start {
				messages = append(messages, bytes.TrimSpace(raw[start:lineStart]))
			}
			haveEnvelope = true
			start = next
		}
		if lineEnd == len(raw) {
			break
		}
		lineStart = next
	}
	if haveEnvelope && start < len(raw) {
		messages = append(messages, bytes.TrimSpace(raw[start:]))
	}
	return messages
}

func isEnvelopeLine(line []byte) bool {
	if !bytes.HasPrefix(line, []byte("From ")) {
		return false
	}
	fields := bytes.Fields(line)
	return len(fields) >= 3
}

func looksLikeHeaders(raw []byte) bool {
	scanner := bufio.NewScanner(io.LimitReader(bytes.NewReader(raw), 64<<10))
	scanner.Buffer(make([]byte, 1024), 64<<10)
	headers := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSuffix(line, "\r") == "" {
			return headers > 0
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		key, _, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) == "" || strings.ContainsAny(key, " \t") {
			return false
		}
		headers++
	}
	return headers > 0
}
