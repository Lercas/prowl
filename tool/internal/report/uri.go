package report

import (
	"net/url"
	"runtime"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
)

func sarifURI(f model.Finding) string {
	address := f.URL
	if address == "" {
		address = f.ArtifactURI
	}
	if address != "" {
		if u, err := url.Parse(escapeURIText(address, "-._~:/?#[]@!$&'()*+,;=")); err == nil {
			u.Scheme = strings.ToLower(u.Scheme)
			// net/url preserves brackets in RawPath, RawQuery and RawFragment, but RFC 3986
			// reserves them for an IP-literal authority. Encode them in the other components.
			u.RawPath = escapeURIText(u.EscapedPath(), "-._~:/@!$&'()*+,;=")
			u.RawQuery = escapeURIText(u.RawQuery, "-._~:/?@!$&'()*+,;=")
			u.RawFragment = escapeURIText(u.EscapedFragment(), "-._~:/?@!$&'()*+,;=")
			u.Opaque = escapeURIText(u.Opaque, "-._~:/@!$&'()*+,;=")
			return u.String()
		}
		// A malformed source locator remains a lossless identifier, rather than invalidating the report.
		return sarifPathURI(address, runtime.GOOS)
	}
	return sarifPathURI(f.Path, runtime.GOOS)
}

func sarifPathURI(path, platform string) string {
	return model.PathURI(path, platform)
}

func asciiLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// escapeURIText preserves existing percent escapes and delimiters, including query ordering.
// Only bytes outside RFC 3986's URI alphabet and malformed percent signs are encoded.
func escapeURIText(s, allowed string) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) && hexDigit(s[i+1]) && hexDigit(s[i+2]) {
			out.WriteString(s[i : i+3])
			i += 2
		} else if asciiLetter(c) || c >= '0' && c <= '9' || strings.ContainsRune(allowed, rune(c)) {
			out.WriteByte(c)
		} else {
			out.WriteByte('%')
			out.WriteByte(hex[c>>4])
			out.WriteByte(hex[c&15])
		}
	}
	return out.String()
}

func hexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
