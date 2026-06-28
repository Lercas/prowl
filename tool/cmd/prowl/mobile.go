package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/source"
)

// cmdMobile unpacks and scans an Android/iOS app (APK/IPA, a local path, or an https URL). The archive
// is just a ZIP: resources/JSON/plist/xml are scanned raw and binary entries (.dex/.arsc/.so/Mach-O)
// get a printable-strings pass so embedded keys surface. Pure-Go, no SDK required.
func cmdMobile(args []string) int {
	c, rest := parseCommon(args)
	setupLogging(c)
	if code := c.mlPreflight(); code != 0 {
		return code
	}
	// The positional target is the first non-flag, ignoring the value of --min-run (which would otherwise
	// be picked up as the target).
	target := firstNonFlag(stripValueFlags(rest, "--min-run"))
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: prowl mobile <app.apk|app.ipa|path|https://…> [scan flags]")
		return 2
	}
	ctx, stop := rootContext(c)
	defer stop()

	localPath := target
	if isURL(target) {
		tmp, err := os.MkdirTemp("", "prowl-mobile-*")
		if err != nil {
			logx.Error("tempdir failed", "err", err)
			return 2
		}
		defer os.RemoveAll(tmp)
		p, derr := downloadToTemp(ctx, target, tmp, c.maxSize, c.timeout)
		if derr != nil {
			logx.Error("mobile download failed", "url", redactURL(target), "err", derr)
			return 2
		}
		localPath = p
	} else if _, err := os.Stat(localPath); err != nil {
		logx.Error("mobile file not found", "path", localPath)
		return 2
	}

	// The app archive is UNTRUSTED — ignore any .prowl.yaml it might bundle (mirrors bucket/repo).
	c.noAutoConfig = true
	cfg := loadConfig(&c)
	det, _, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}

	opts := source.MobileOptions{
		MaxBytes: c.maxSize,
		Exclude:  c.exclude,
		Strings:  !hasFlag(rest, "--no-strings"),
		MinRun:   minRunDefault,
	}
	if v := flagVal(rest, "--min-run"); v != "" {
		opts.MinRun = mustInt("--min-run", v, 1)
	}

	logx.Info("scanning mobile app", "path", localPath)
	items, err := source.MobileItems(ctx, localPath, opts)
	if err != nil {
		logx.Error("mobile extract failed", "path", localPath, "err", err)
		return 2
	}
	// dedupe on by default: the same key often shows up in several entries (raw resource + dex strings);
	// report it once. Same as cmdImage.
	return runScan(ctx, c, cfg, det, items, c.dedupe)
}

// minRunDefault mirrors source's default min printable-run length (kept here so the flag default reads
// at the call site without exporting an internal const).
const minRunDefault = 5

// isURL reports whether target is an http(s) URL to download rather than a local path.
func isURL(target string) bool {
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}

// downloadToTemp fetches url into dir and returns the saved path. It uses safehttp.Client (NOT
// http.DefaultClient) so an attacker-supplied URL pointing at loopback / cloud metadata (169.254.169.254)
// is refused at dial. The body is bounded so a huge download can't fill the disk — the archive may be
// larger than a single entry, so the budget is a multiple of --max-size.
func downloadToTemp(ctx context.Context, rawURL, dir string, maxBytes int64, timeout time.Duration) (string, error) {
	// safehttp.Client defaults a zero/negative timeout to a sane value, so a no-flag run is still bounded.
	client := safehttp.Client(timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download %s: unexpected status %s", redactURL(rawURL), resp.Status)
	}
	dst := filepath.Join(dir, downloadName(rawURL))
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	limit := maxBytes * 4
	if limit <= 0 {
		limit = 64 << 20
	}
	if _, err := io.Copy(f, io.LimitReader(resp.Body, limit)); err != nil {
		return "", err
	}
	return dst, nil
}

// downloadName derives a safe local filename from a URL's path. zip.OpenReader ignores the extension
// (classifyEntry keys on internal entry names), so an .ipa-vs-.apk guess is cosmetic; we only avoid an
// empty/odd name and never use a path component that isn't a final filename.
func downloadName(rawURL string) string {
	p := rawURL
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i] // drop query/fragment
	}
	urlPath := p
	if u, err := url.Parse(rawURL); err == nil {
		urlPath = u.Path
	}
	// Decide the .ipa-vs-.apk fallback from the path with any trailing slashes trimmed, so a directory
	// URL like ".../x.ipa/" still maps to app.ipa.
	fallback := "app.apk"
	if strings.HasSuffix(strings.ToLower(strings.TrimRight(urlPath, "/")), ".ipa") {
		fallback = "app.ipa"
	}
	// A trailing slash means the path is a directory, not a file — fall back.
	if strings.HasSuffix(p, "/") {
		return fallback
	}
	base := path.Base(urlPath) // URL paths are '/'-separated regardless of OS
	if base == "" || base == "." || base == "/" {
		return fallback
	}
	return base
}
