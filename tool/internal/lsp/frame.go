package lsp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"mime"
	"strconv"
	"strings"
)

const maxHeaderBytes = 16 << 10 // Includes every CRLF and the terminating empty line.

// Only errors with a consumed, unambiguous body can leave the connection synchronized.
var (
	errBadFrame   = errors.New("lsp: unsupported or invalid content type")
	errFatalFrame = errors.New("lsp: invalid or incomplete message frame")
)

func readMessage(r *bufio.Reader) ([]byte, error) {
	length, used := -1, 0
	contentTypeSeen, badContentType := false, false
	for {
		line, consumed, err := readHeaderLine(r, maxHeaderBytes-used)
		used += consumed
		if err != nil {
			if errors.Is(err, io.EOF) && used == 0 {
				return nil, io.EOF
			}
			return nil, errFatalFrame
		}
		if len(line) == 0 {
			break
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !headerName(line[:colon]) || !headerValue(line[colon+1:]) {
			return nil, errFatalFrame
		}
		name := strings.ToLower(string(line[:colon]))
		value := strings.Trim(string(line[colon+1:]), " \t")
		switch name {
		case "content-length":
			// Never pick a preferred duplicate or look for this token inside another field/body.
			if length >= 0 {
				return nil, errFatalFrame
			}
			length, err = contentLength(value)
			if err != nil {
				return nil, errFatalFrame
			}
		case "content-type":
			badContentType = badContentType || contentTypeSeen || !utf8ContentType(value)
			contentTypeSeen = true
		}
	}
	if length < 0 {
		return nil, errFatalFrame
	}
	if badContentType {
		// Discard exactly the trusted byte count; do not search rejected content for new frames.
		if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
			return nil, errFatalFrame
		}
		return nil, errBadFrame
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, errFatalFrame
	}
	return body, nil
}

func readHeaderLine(r *bufio.Reader, remaining int) ([]byte, int, error) {
	if remaining <= 0 {
		return nil, 0, errFatalFrame
	}
	var line []byte
	for {
		fragment, err := r.ReadSlice('\n')
		if len(fragment) > remaining-len(line) {
			return nil, len(line) + len(fragment), errFatalFrame
		}
		line = append(line, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return nil, len(line), err
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, len(line), errFatalFrame
		}
		return line[:len(line)-2], len(line), nil
	}
}

func headerName(name []byte) bool {
	for _, b := range name {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b)) {
			return false
		}
	}
	return true
}

func headerValue(value []byte) bool {
	for _, b := range value {
		if b != '\t' && (b < ' ' || b >= 0x7f) {
			return false
		}
	}
	return true
}

func contentLength(value string) (int, error) {
	if value == "" {
		return 0, errFatalFrame
	}
	for _, b := range []byte(value) {
		if b < '0' || b > '9' {
			return 0, errFatalFrame
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n > maxMessageBytes {
		return 0, errFatalFrame
	}
	return int(n), nil // Conversion is bounded by maxMessageBytes on every platform.
}

func utf8ContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || !strings.Contains(mediaType, "/") {
		return false
	}
	charset, exists := parameters["charset"]
	return !exists || strings.EqualFold(charset, "utf-8") || strings.EqualFold(charset, "utf8")
}
