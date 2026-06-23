package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Signer adds provider-specific request signing that YAML interpolation can't express (AWS SigV4,
// etc.), from the detected value, the extracted context values, and the verifier's sign_params.
type Signer func(req *http.Request, body []byte, value string, extracted, params map[string]string) error

var signers = map[string]Signer{
	"awsv4": signAWSv4,
}

// now is overridable in tests.
var now = time.Now

// signAWSv4 applies AWS Signature Version 4 using an access-key-id + secret-access-key pair from
// context (falling back to the detected value). Region/service come from sign_params.
func signAWSv4(req *http.Request, body []byte, value string, extracted, params map[string]string) error {
	keyID := firstNonEmpty(extracted["aws_access_key_id"], extracted["access_key_id"])
	secret := firstNonEmpty(extracted["aws_secret_access_key"], extracted["secret_access_key"], value)
	if keyID == "" || secret == "" {
		return fmt.Errorf("awsv4: need both access-key-id and secret (found id=%v)", keyID != "")
	}
	service := orDefault(params["service"], "sts")
	region := orDefault(params["region"], "us-east-1")

	t := now().UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	host := req.URL.Host

	req.Header.Set("X-Amz-Date", amzDate)
	if tok := extracted["aws_session_token"]; tok != "" {
		req.Header.Set("X-Amz-Security-Token", tok)
	}
	ctype := req.Header.Get("Content-Type")

	payloadHash := sha256Hex(body)
	// canonical headers must be sorted by name for the signature to match
	hdrs := map[string]string{"host": host, "x-amz-date": amzDate}
	if ctype != "" {
		hdrs["content-type"] = ctype
	}
	if tok := req.Header.Get("X-Amz-Security-Token"); tok != "" {
		hdrs["x-amz-security-token"] = tok
	}
	names := make([]string, 0, len(hdrs))
	for k := range hdrs {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + hdrs[k] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	canonURI := req.URL.EscapedPath()
	if canonURI == "" {
		canonURI = "/"
	}
	canonRequest := strings.Join([]string{
		req.Method, canonURI, canonicalQuery(req.URL.RawQuery), canonHeaders.String(), signedHeaders, payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		keyID, scope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
	return nil
}

// canonicalQuery builds the SigV4 canonical query string from the raw (wire-encoded) RawQuery,
// re-encoding each key/value without a url.QueryUnescape pass so the canonical form matches the
// bytes on the wire (a QueryUnescape would turn a literal '+' into "%20" while the wire keeps it ->
// SignatureDoesNotMatch). Pairs are sorted by encoded key then value.
func canonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		// Re-encode raw bytes so canonical == wire; awsURIEncode leaves valid %XX escapes intact.
		pairs = append(pairs, kv{awsURIEncode(k), awsURIEncode(v)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

// awsURIEncode percent-encodes per AWS SigV4 rules: unreserved chars (A-Z a-z 0-9 - _ . ~) pass
// through, everything else becomes %XX (uppercase hex). An existing valid %XX triplet is passed
// through verbatim so already-encoded raw query bytes aren't double-encoded.
func awsURIEncode(s string) string {
	const upperhex = "0123456789ABCDEF"
	isHex := func(c byte) bool {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		// Pass through an existing valid %XX escape unchanged (uppercasing the hex digits).
		if c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte('%')
			b.WriteByte(upperhex[hexVal(s[i+1])])
			b.WriteByte(upperhex[hexVal(s[i+2])])
			i += 2
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperhex[c>>4])
		b.WriteByte(upperhex[c&0xf])
	}
	return b.String()
}

// hexVal returns the value of a single hex digit (caller guarantees c is a valid hex digit).
func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default: // 'A'-'F'
		return c - 'A' + 10
	}
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
