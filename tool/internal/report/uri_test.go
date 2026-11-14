package report

import (
	"bytes"
	"encoding/json"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestSARIFFileURIRoundTrip(t *testing.T) {
	for _, path := range []string{"src/a#b?.env", "a%20b.env", "Ключ 😀.env", "line\nbreak.env", "name:part.env", "//literal/double-slash.env", `a\b.env`, "https://literal/local#name.env"} {
		f := model.Finding{Type: "owned", Severity: "high", Path: path, Line: 2, Col: 3, Redacted: "****", Fingerprint: "stable"}
		var buf bytes.Buffer
		if err := Write(&buf, []model.Finding{f}, "sarif", false); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Runs []struct {
				Results []struct {
					Locations []struct {
						PhysicalLocation struct{ ArtifactLocation struct{ URI string } }
					}
				}
			}
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		uri := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
		if runtime.GOOS == "windows" {
			if uri != sarifPathURI(path, "windows") {
				t.Fatal("renderer does not use the host path convention")
			}
			continue
		}
		u, err := url.Parse(uri)
		wantScheme := ""
		if strings.HasPrefix(path, "/") {
			wantScheme = "file"
		}
		if err != nil || u.Scheme != wantScheme || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || u.Path != path {
			t.Errorf("file path %q was reinterpreted: uri=%q parsed=%+v error=%v", path, uri, u, err)
		}
	}
}

func TestSARIFPathPlatforms(t *testing.T) {
	for _, tc := range []struct{ platform, path, want string }{
		{"linux", "/home/Ключ #?%20.env", "file:///home/%D0%9A%D0%BB%D1%8E%D1%87%20%23%3F%2520.env"},
		{"darwin", `a\b.env`, "a%5Cb.env"},
		{"linux", "https://literal/a#b?.env", "https%3A//literal/a%23b%3F.env"},
		{"windows", `C:\Users\Ключ #?%20.env`, "file:///C:/Users/%D0%9A%D0%BB%D1%8E%D1%87%20%23%3F%2520.env"},
		{"windows", `\\server\share\a#b?.env`, "file://server/share/a%23b%3F.env"},
		{"windows", `\\?\C:\a%20.env`, "file:///C:/a%2520.env"},
		{"windows", `\\?\UNC\server\share\a%20.env`, "file://server/share/a%2520.env"},
		{"windows", `src\a#b?.env`, "src/a%23b%3F.env"},
		{"windows", `C:relative.env`, "C%3Arelative.env"},
		{"windows", `\rooted\a.env`, "file:///rooted/a.env"},
	} {
		if got := sarifPathURI(tc.path, tc.platform); got != tc.want {
			t.Errorf("%s path %q: got %q, want %q", tc.platform, tc.path, got, tc.want)
		}
	}
}

func TestSARIFSourceURIPriorityAndEscapes(t *testing.T) {
	f := model.Finding{Path: "https://literal/local#filename", ArtifactURI: "https://owned.invalid/source%23file?x=%2F#state"}
	if got := sarifURI(f); got != f.ArtifactURI {
		t.Fatalf("source locator lost: %q", got)
	}
	f.URL = "https://owned.invalid/direct"
	if got := sarifURI(f); got != f.URL {
		t.Fatal("direct URL does not take priority")
	}
	f.URL = "https://owned.invalid/a[b]?q=[x]&q=Ключ 😀&literal=%20&bad=%z#место[]"
	got := sarifURI(f)
	u, err := url.Parse(got)
	if err != nil || u.Path != "/a[b]" || u.RawQuery != "q=%5Bx%5D&q=%D0%9A%D0%BB%D1%8E%D1%87%20%F0%9F%98%80&literal=%20&bad=%25z" || u.Fragment != "место[]" {
		t.Fatalf("URL query or escaping changed meaning: %q (%v)", got, err)
	}
	if strings.ContainsAny(got, "[]") {
		t.Fatal("path/query/fragment brackets must be percent-encoded")
	}
	f.URL = "http://[invalid"
	u, err = url.Parse(sarifURI(f))
	if err != nil || u.Path != f.URL || u.Scheme != "" || u.Host != "" {
		t.Fatal("malformed URL invalidated the report or lost its identity")
	}
	var buf bytes.Buffer
	if err := Write(&buf, []model.Finding{f}, "json", false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "ArtifactURI") || strings.Contains(buf.String(), f.ArtifactURI) {
		t.Fatal("private URI metadata leaked into JSON")
	}
}

func FuzzSARIFPathURI(f *testing.F) {
	for _, path := range []string{"", "src/a#b?.env", "name:part", "//local/file", "https://literal/file", "Ключ 😀", "invalid\xff\x00\n"} {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if len(path) > 64*1024 {
			t.Skip()
		}
		uri := sarifPathURI(path, "linux")
		u, err := url.Parse(uri)
		wantScheme := ""
		if strings.HasPrefix(path, "/") {
			wantScheme = "file"
		}
		if err != nil || u.Path != path || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || u.Scheme != wantScheme {
			t.Fatalf("literal path was reinterpreted: %q -> %q (%v)", path, uri, err)
		}
		for _, c := range []byte(uri) {
			if c <= ' ' || c >= 0x7f {
				t.Fatalf("not an ASCII URI: %q", uri)
			}
		}
	})
}

func TestSARIFDirectURLKeepsURISemantics(t *testing.T) {
	for _, address := range []string{"https://owned.invalid/a%23b?x=%2F#section", "https://owned.invalid/Ключ 😀?q=one%20two#место"} {
		f := model.Finding{URL: address, Path: "page title"}
		original, err := url.Parse(address)
		if err != nil {
			t.Fatal(err)
		}
		uri := sarifURI(f)
		parsed, err := url.Parse(uri)
		if err != nil || parsed.Scheme != original.Scheme || parsed.Host != original.Host || parsed.Path != original.Path || parsed.RawQuery != original.RawQuery || parsed.Fragment != original.Fragment {
			t.Fatalf("URL changed meaning: %q -> %q", address, uri)
		}
		for _, c := range []byte(uri) {
			if c <= ' ' || c >= 0x7f {
				t.Errorf("URL is not an escaped ASCII URI: %q", uri)
				break
			}
		}
	}
}
