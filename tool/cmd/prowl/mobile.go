package main

import (
	"context"
	"fmt"
	"io"
	"math"
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
	c, rest, err := parseCommand("mobile", args)
	if err != nil {
		return commandParseError(err)
	}
	if code := rejectUnsupportedOCR(c, "mobile"); code != 0 {
		return code
	}
	setupLogging(c)
	if code := c.mlPreflight(); code != 0 {
		return code
	}
	// The command parser has already separated the target from option values.
	target := ""
	if len(rest) == 1 {
		target = rest[0]
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: prowl mobile <app.apk|app.ipa|path|https://…> [scan flags]")
		return 2
	}
	ctx, stop := rootContext(c)
	defer stop()
	// Load trusted explicit config before deriving download and extraction limits.
	c.noAutoConfig = true
	cfg, err := loadConfig(&c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}

	det, _, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}

	eng, err := loadEngine(c)
	if err != nil {
		logx.Error("rule setup failed", "err", err)
		return 2
	}
	vset, verr := loadVerifySet(c)
	if verr != nil {
		logx.Error("verify setup failed", "err", verr)
		return 2
	}

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
	} else if _, err := os.Stat(localPath); err != nil { // #nosec G703 -- explicitly selected local scanner input, not a sandboxed server path.
		logx.Error("mobile file not found", "path", localPath)
		return 2
	}

	opts := source.MobileOptions{
		MaxBytes: c.maxSize,
		Exclude:  c.exclude,
		Strings:  !c.cmd.noStrings,
		MinRun:   c.cmd.minRun,
	}

	logx.Info("scanning mobile app", "path", localPath)
	items, err := source.MobileItems(ctx, localPath, opts)
	if err != nil {
		logx.Error("mobile extract failed", "path", localPath, "err", err)
		return 2
	}
	// dedupe on by default: the same key often shows up in several entries (raw resource + dex strings);
	// report it once. Same as cmdImage.
	return runPreparedScan(ctx, c, cfg, det, eng, vset, items, c.dedupe)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil) // #nosec G704 -- safehttp.Client enforces resolved-IP and redirect guards at dial time.
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req) // #nosec G704 -- guarded safehttp transport; covered by TestDownloadToTempSSRF.
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download %s: unexpected status %s", redactURL(rawURL), resp.Status)
	}
	dst := filepath.Join(dir, downloadName(rawURL))
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G703 -- safe basename in an owned private directory; never replaces an existing entry.
	if err != nil {
		return "", err
	}
	defer f.Close()
	limit := mobileDownloadLimit(maxBytes)
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", fmt.Errorf("mobile download exceeds the %d-byte size limit", limit)
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return dst, nil
}

func mobileDownloadLimit(maxBytes int64) int64 {
	if maxBytes <= 0 {
		return 64 << 20
	}
	if maxBytes > (math.MaxInt64-1)/4 {
		return math.MaxInt64 - 1 // reserve one byte for overflow detection
	}
	return maxBytes * 4
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
	if base == "" || base == "." || base == ".." || base == "/" || strings.ContainsAny(base, "\\:\x00") {
		return fallback
	}
	return base
}
