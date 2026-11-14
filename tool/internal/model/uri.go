package model

import (
	"net/url"
	"strings"
)

// PathURI encodes a literal path using the source platform's separator/volume conventions.
// It does not resolve or clean paths: acquisition must supply physical provenance when needed.
func PathURI(path, platform string) string {
	u := &url.URL{}
	if platform == "windows" {
		path = strings.ReplaceAll(path, `\`, "/")
		if strings.HasPrefix(path, "//?/") {
			path = path[4:]
			if strings.HasPrefix(strings.ToUpper(path), "UNC/") {
				path = "//" + path[4:]
			}
		}
		drive := len(path) >= 3 && path[1] == ':' && path[2] == '/' &&
			(path[0] >= 'a' && path[0] <= 'z' || path[0] >= 'A' && path[0] <= 'Z')
		if drive {
			u.Scheme, path = "file", "/"+path
		} else if strings.HasPrefix(path, "//") {
			u.Host, path, _ = strings.Cut(path[2:], "/")
			u.Scheme, path = "file", "/"+path
		}
	}
	if u.Scheme == "" && strings.HasPrefix(path, "/") {
		u.Scheme = "file"
	}
	u.Path = path
	if u.Scheme == "" {
		// A colon in the first segment must not turn a relative path into a URI scheme.
		first, rest, found := strings.Cut(u.EscapedPath(), "/")
		u.RawPath = strings.ReplaceAll(first, ":", "%3A")
		if found {
			u.RawPath += "/" + rest
		}
	}
	return u.String()
}
