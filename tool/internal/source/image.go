package source

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// Extraction budgets that bound an image scan against a decompression bomb. The per-file --max-size
// caps a single file, but these cap the cumulative cost that many under-cap files could still rack up.
// Vars (not consts) only so tests can shrink them.
var (
	// maxImageTotalBytes caps the sum of all extracted file bodies across every layer.
	maxImageTotalBytes int64 = 2 << 30 // 2 GiB
	// maxImageEntries caps the total tar entries inspected (a tar can declare millions of tiny entries).
	maxImageEntries = 500_000
	// maxImageLayers caps how many layers are walked (a manifest can list an absurd number).
	maxImageLayers = 1000
)

// imageBudget tracks cumulative extraction cost across all layers; once any cap is exceeded it records
// an error so extraction aborts.
type imageBudget struct {
	totalBytes int64
	entries    int
	err        error
}

// addEntry charges one tar entry of bodyBytes against the budget. It returns false (and sets b.err
// once) when a cap is crossed, signalling the caller to abort the whole scan.
func (b *imageBudget) addEntry(bodyBytes int64) bool {
	if b.err != nil {
		return false
	}
	b.entries++
	if b.entries > maxImageEntries {
		b.err = fmt.Errorf("image extraction aborted: exceeded the %d-entry cap (possible decompression bomb)", maxImageEntries)
		return false
	}
	b.totalBytes += bodyBytes
	if b.totalBytes > maxImageTotalBytes {
		b.err = fmt.Errorf("image extraction aborted: extracted bytes exceeded the %d-byte cap (reached %d; possible decompression bomb)", maxImageTotalBytes, b.totalBytes)
		return false
	}
	return true
}

// Image pulls an OCI/Docker image and yields its config and per-layer file contents as Items.
//
// It scans every layer (not just the flattened filesystem): a secret COPYd in one layer and `rm`d in a
// later one vanishes from the final filesystem but persists, recoverable, in the earlier layer. The
// config is scanned too (env vars and RUN commands are prime secret locations).
//
// Auth uses the default keychain (~/.docker/config.json). The pull is synchronous so its failure is
// returned to the caller; it is retried for transient failures, each attempt bounded by its own
// timeout. Layer bodies are then read lazily in a background goroutine, staying bound to ctx.
func Image(ctx context.Context, ref string, maxBytes int64, timeout time.Duration, exclude []string) (<-chan model.Item, error) {
	perAttempt := fetchTimeout(timeout)
	var (
		img       v1.Image
		keepAlive context.CancelFunc // cancel of the winning attempt's ctx; lives until extraction ends
	)
	err := resilience.Retry(ctx, 3, 500*time.Millisecond, 5*time.Second, func() error {
		// go-containerregistry reuses this attempt's context for the lazy layer/config reads, so on
		// success we must NOT cancel it here — its cancel is handed to the extraction goroutine instead.
		actx, cancel := context.WithTimeout(ctx, perAttempt)
		// Pull through safehttp's guarded transport: its dial-time Control hook refuses internal address
		// space, so an SSRF ref (e.g. cloud metadata at 169.254.169.254) is blocked at connect. Crane's
		// default transport would dial it. Re-derived per attempt for this attempt's connect timeout.
		got, perr := crane.Pull(ref, crane.WithContext(actx), crane.WithTransport(safehttp.SafeTransport(perAttempt)))
		if perr != nil {
			cancel()
			if ctx.Err() != nil { // parent cancelled (Ctrl-C / overall --timeout): give up, don't retry
				return ctx.Err()
			}
			if actx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("pull image %q timed out after %s", ref, perAttempt)
			}
			return fmt.Errorf("pull image %q: %w", ref, perr)
		}
		img, keepAlive = got, cancel
		return nil
	})
	if err != nil {
		return nil, err
	}

	ch := make(chan model.Item, 128)
	go func() {
		defer close(ch)
		if keepAlive != nil {
			defer keepAlive() // release the pull context once every layer has been read
		}
		// A malformed tar entry or a layer read panic must not crash the process or skip close(ch).
		resilience.Guard(
			func() { emitImage(ctx, ch, img, maxBytes, exclude) },
			func(r any) { logx.Warn("recovered image-scan panic", "err", r) },
		)
	}()
	return ch, nil
}

// emitImage emits the image config then walks every layer's tar, sending each regular file's
// content as a model.Item. It stops early when ctx is cancelled.
func emitImage(ctx context.Context, ch chan<- model.Item, img v1.Image, maxBytes int64, exclude []string) {
	if !emitConfig(ctx, ch, img) {
		return
	}
	layers, err := img.Layers()
	if err != nil {
		logx.Error("cannot read image layers", "err", err)
		return
	}
	// Reject an absurd layer count before reading any layer (a bomb multiplies per-layer expansion).
	if len(layers) > maxImageLayers {
		logx.Error("image extraction aborted: too many layers (possible decompression bomb)",
			"layers", len(layers), "limit", maxImageLayers)
		return
	}
	budget := &imageBudget{}
	for i, layer := range layers {
		if ctx.Err() != nil {
			return
		}
		if !emitLayer(ctx, ch, i, layer, maxBytes, exclude, budget) {
			// A budget abort (vs. a consumer stop) carries an error; surface it so the scan doesn't end
			// silently as if the image were clean.
			if budget.err != nil {
				logx.Error("image scan stopped", "err", budget.err)
			}
			return
		}
	}
}

// emitConfig emits the image's env vars, labels, and build-history commands as Items (the prime
// non-filesystem secret locations). Returns false if the consumer asked to stop.
func emitConfig(ctx context.Context, ch chan<- model.Item, img v1.Image) bool {
	cfg, err := img.ConfigFile()
	if err != nil || cfg == nil {
		if err != nil {
			logx.Warn("cannot read image config", "err", err)
		}
		return true
	}
	if env := strings.Join(cfg.Config.Env, "\n"); env != "" {
		if !send(ctx, ch, model.Item{Text: env, Source: "code", Path: "image:config/env"}) {
			return false
		}
	}
	if labels := joinLabels(cfg.Config.Labels); labels != "" {
		if !send(ctx, ch, model.Item{Text: labels, Source: "code", Path: "image:config/labels"}) {
			return false
		}
	}
	var hist []string
	for _, h := range cfg.History {
		if h.CreatedBy != "" {
			hist = append(hist, h.CreatedBy)
		}
	}
	if h := strings.Join(hist, "\n"); h != "" {
		if !send(ctx, ch, model.Item{Text: h, Source: "code", Path: "image:config/history"}) {
			return false
		}
	}
	return true
}

// joinLabels renders the label map as deterministic "key=value" lines (sorted so the scan output
// is stable across runs).
func joinLabels(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
	}
	return b.String()
}

// emitLayer opens one layer's uncompressed tar and emits each regular file as an Item. Returns false
// when the consumer asked to stop OR the cumulative extraction budget (b) was blown — the caller
// inspects b.err to tell the two apart.
func emitLayer(ctx context.Context, ch chan<- model.Item, idx int, layer v1.Layer, maxBytes int64, exclude []string, b *imageBudget) bool {
	rc, err := layer.Uncompressed()
	if err != nil {
		logx.Warn("cannot read layer", "layer", idx, "err", err)
		return true
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		if ctx.Err() != nil {
			return false
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			return true
		}
		if err != nil {
			logx.Warn("corrupt layer tar", "layer", idx, "err", err)
			return true
		}
		// Charge every header against the budget BEFORE per-entry filtering: a bomb of millions of empty
		// entries each `continue`s below but together exhausts CPU. addEntry also charges the declared
		// body size against the total-bytes cap, catching gigabytes spread across under-cap entries.
		charge := hdr.Size
		if charge < 0 {
			charge = 0
		}
		if !b.addEntry(charge) {
			return false // budget blown (b.err set); abort the whole image scan
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size <= 0 || hdr.Size > maxBytes {
			continue
		}
		if skipExt[strings.ToLower(filepath.Ext(hdr.Name))] {
			continue
		}
		excluded := false
		for _, ex := range exclude {
			// Same matcher as the filesystem source (config.PathMatch: glob OR substring), so
			// `--exclude '*.lock'` matches here; a raw strings.Contains never matched a glob.
			if config.PathMatch(ex, hdr.Name) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		content := make([]byte, hdr.Size)
		n, err := io.ReadFull(tr, content)
		if err != nil && err != io.ErrUnexpectedEOF {
			logx.Debug("layer file read error", "layer", idx, "path", hdr.Name, "err", err)
			continue
		}
		content = content[:n]
		text, ok := scannableText(content)
		if !ok {
			logx.Debug("skipped: binary layer file", "layer", idx, "path", hdr.Name)
			continue
		}
		if !send(ctx, ch, model.Item{
			Text:   string(text),
			Source: "code",
			Path:   fmt.Sprintf("layer%d:%s", idx, hdr.Name),
		}) {
			return false
		}
	}
}
