package source

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// ImageInput selects acquisition; ImageAuto detects by Stat, the rest are the --image-input escape hatch.
type ImageInput int

const (
	ImageAuto   ImageInput = iota
	ImageRef               // a remote registry reference (pulled through the SSRF-guarded transport)
	ImageTar               // a local docker-save / OCI tarball
	ImageOCIDir            // a local OCI image-layout directory
	ImageStdin             // a tar stream on stdin ("-")
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

// Image acquires an image (remote ref / local tarball / OCI-layout dir / stdin per kind) and yields its
// config and EVERY layer's files as Items — a secret COPYd then rm'd survives in the earlier layer. Only
// remote refs hit the network (SSRF-guarded); one anti-bomb budget is shared across all images.
func Image(ctx context.Context, arg string, kind ImageInput, maxBytes int64, timeout time.Duration, exclude []string) (<-chan model.Item, *FinalIndex, error) {
	imgs, cleanup, err := resolveImages(ctx, arg, kind, timeout)
	if err != nil {
		return nil, nil, err
	}
	fi := newFinalIndex() // read only after ch drains
	ch := make(chan model.Item, 128)
	go func() {
		defer close(ch)
		defer func() {
			if ctx.Err() != nil { // cancelled mid-walk: the flatten map is partial -> verdicts unknown
				fi.markAborted()
			}
		}()
		if cleanup != nil {
			defer cleanup() // release the pull ctx / remove the stdin spool once every layer is read
		}
		budget := &imageBudget{} // one cumulative anti-bomb budget across every image of this invocation
		for i, img := range imgs {
			if ctx.Err() != nil {
				return
			}
			label := imageLabel(arg, i, len(imgs)) // prefix so findings from distinct images never collide
			img := img
			resilience.Guard(
				func() { emitImage(ctx, ch, img, label, maxBytes, exclude, budget, fi) },
				// a recovered panic cut the layer walk short — mark aborted so the scan fails closed (exit 2),
				// never certifies the image clean (mirrors the budget-abort and ctx-cancel paths).
				func(r any) {
					fi.markAborted()
					logx.Warn("recovered image-scan panic — results incomplete", "err", r)
				},
			)
			if budget.err != nil { // a decompression-bomb abort is global — stop the whole batch
				fi.markAborted() // partial flatten map: every verdict becomes unknown
				logx.Error("image scan stopped", "err", budget.err)
				return
			}
		}
	}()
	return ch, fi, nil
}

// resolveImages picks the acquisition path by Stat (not name.ParseReference — too permissive): "-"=stdin,
// dir=OCI layout, file=tarball, else remote. Only the remote branch touches the network.
func resolveImages(ctx context.Context, arg string, kind ImageInput, timeout time.Duration) ([]v1.Image, func(), error) {
	if kind == ImageAuto {
		if arg == "-" {
			kind = ImageStdin
		} else if fi, err := os.Stat(arg); err == nil {
			if fi.IsDir() {
				kind = ImageOCIDir
			} else {
				kind = ImageTar
			}
		} else {
			kind = ImageRef
		}
	}
	switch kind {
	case ImageStdin:
		return loadStdin()
	case ImageTar:
		return loadTarball(arg)
	case ImageOCIDir:
		return loadOCILayout(arg)
	default: // ImageRef
		return pullRemote(ctx, arg, timeout)
	}
}

// pullRemote pulls a ref through the SSRF-guarded transport (blocks internal addrs like 169.254.169.254),
// retried per-attempt. keepAlive isn't cancelled here — crane reuses the ctx for lazy reads — but returned.
func pullRemote(ctx context.Context, ref string, timeout time.Duration) ([]v1.Image, func(), error) {
	perAttempt := fetchTimeout(timeout)
	var (
		img       v1.Image
		keepAlive context.CancelFunc
	)
	err := resilience.Retry(ctx, 3, 500*time.Millisecond, 5*time.Second, func() error {
		actx, cancel := context.WithTimeout(ctx, perAttempt)
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
		return nil, nil, err
	}
	return []v1.Image{img}, func() {
		if keepAlive != nil {
			keepAlive()
		}
	}, nil
}

// loadTarball reads every image in a local docker-save / OCI tarball — no network, no SSRF transport.
func loadTarball(p string) ([]v1.Image, func(), error) {
	imgs, err := imagesFromTar(func() (io.ReadCloser, error) { return os.Open(p) }, p)
	if err != nil {
		return nil, nil, err
	}
	return imgs, nil, nil
}

// imagesFromTar loads every image a docker-save tarball lists in its manifest, so a MULTI-image save is
// not silently rejected the way tarball.ImageFromPath(.,nil) is. Falls back to the single-image read.
func imagesFromTar(opener tarball.Opener, label string) ([]v1.Image, error) {
	m, err := tarball.LoadManifest(opener)
	if err != nil || len(m) <= 1 {
		img, ferr := tarball.Image(opener, nil)
		if ferr != nil {
			return nil, fmt.Errorf("load image tarball %q: %w", label, ferr)
		}
		return []v1.Image{img}, nil
	}
	var imgs []v1.Image
	for _, d := range m {
		var tag *name.Tag
		if len(d.RepoTags) > 0 {
			if t, terr := name.NewTag(d.RepoTags[0]); terr == nil {
				tag = &t
			}
		}
		img, ierr := tarball.Image(opener, tag)
		if ierr != nil {
			logx.Warn("skip unloadable image in tarball", "tags", d.RepoTags, "err", ierr)
			continue
		}
		imgs = append(imgs, img)
	}
	if len(imgs) == 0 {
		return nil, fmt.Errorf("tarball %q contains no loadable images", label)
	}
	return imgs, nil
}

// loadOCILayout reads a local OCI image-layout dir, flattening its index to every contained image.
func loadOCILayout(dir string) ([]v1.Image, func(), error) {
	idx, err := layout.ImageIndexFromPath(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("load OCI layout %q: %w", dir, err)
	}
	imgs, err := flattenIndex(idx)
	if err != nil {
		return nil, nil, fmt.Errorf("read OCI layout %q: %w", dir, err)
	}
	if len(imgs) == 0 {
		return nil, nil, fmt.Errorf("OCI layout %q contains no image manifests", dir)
	}
	return imgs, nil, nil
}

// loadStdin spools stdin to a seekable temp file, capped so a gz-huge bomb is rejected before any read.
func loadStdin() ([]v1.Image, func(), error) {
	f, err := os.CreateTemp("", "prowl-image-*.tar")
	if err != nil {
		return nil, nil, fmt.Errorf("spool stdin: %w", err)
	}
	tmp := f.Name()
	n, cerr := io.Copy(f, io.LimitReader(os.Stdin, maxImageTotalBytes+1))
	closeErr := f.Close()
	if cerr != nil || closeErr != nil {
		os.Remove(tmp)
		return nil, nil, fmt.Errorf("spool stdin: %w", cmp(cerr, closeErr))
	}
	if n > maxImageTotalBytes {
		os.Remove(tmp)
		return nil, nil, fmt.Errorf("stdin image exceeded the %d-byte cap (possible decompression bomb)", maxImageTotalBytes)
	}
	imgs, err := imagesFromTar(func() (io.ReadCloser, error) { return os.Open(tmp) }, "stdin")
	if err != nil {
		os.Remove(tmp)
		return nil, nil, err
	}
	return imgs, func() { os.Remove(tmp) }, nil
}

// cmp returns the first non-nil error.
func cmp(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

// flattenIndex collects every image manifest, descending nested (multi-arch) indexes and skipping
// non-images. A visited-digest set + depth bound stop a crafted self-referential index from recursing
// forever (a Go stack overflow recover() cannot catch).
func flattenIndex(idx v1.ImageIndex) ([]v1.Image, error) {
	return flattenIndexInto(idx, map[v1.Hash]bool{}, 0)
}

func flattenIndexInto(idx v1.ImageIndex, seen map[v1.Hash]bool, depth int) ([]v1.Image, error) {
	if depth > 32 {
		return nil, fmt.Errorf("OCI index nested too deeply (possible cycle)")
	}
	mf, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	var out []v1.Image
	for _, desc := range mf.Manifests {
		switch {
		case desc.MediaType.IsIndex():
			if seen[desc.Digest] { // already descended this index — cycle, skip
				continue
			}
			seen[desc.Digest] = true
			child, err := idx.ImageIndex(desc.Digest)
			if err != nil {
				return nil, err
			}
			imgs, err := flattenIndexInto(child, seen, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, imgs...)
		case desc.MediaType.IsImage():
			img, err := idx.Image(desc.Digest)
			if err != nil {
				return nil, err
			}
			out = append(out, img)
		}
	}
	return out, nil
}

// FinalIndex maps (image label, clean path) to the highest layer owning the path after OCI whiteouts, so
// a finding's layer can be told from the final flattened image. Built during the sequential walk; read
// only after the Items channel drains. aborted/degraded force "unknown" so a partial map never downgrades.
type FinalIndex struct {
	mu        sync.Mutex
	owner     map[string]int
	labels    map[string]bool // image labels this index has folded (a foreign label reads as unknown)
	sweepWork map[string]int  // per-label cumulative cost of opaque/dir subtree sweeps (DoS guard)
	aborted   bool            // the anti-bomb budget tripped mid-walk (global to the invocation)
	degraded  map[string]bool // per-label: one image's blowup must not poison a sibling arch's attribution
}

func newFinalIndex() *FinalIndex {
	return &FinalIndex{owner: map[string]int{}, labels: map[string]bool{},
		sweepWork: map[string]int{}, degraded: map[string]bool{}}
}

const (
	finalIndexMaxPaths = 300_000 // bound memory
	// finalIndexMaxSweepWork bounds the cumulative O(n) opaque/dir-whiteout sweeps against a CPU DoS while
	// staying generous enough for real images (hundreds of whiteouts on a large tree ~1e8). ~500M
	// comparisons is well under a second; a true bomb (500k whiteout entries) still trips it.
	finalIndexMaxSweepWork = 500_000_000
)

func finalKey(label, clean string) string { return label + "\x00" + clean }

// apply folds one tar header into the flatten map — called for EVERY header before filtering, so a
// non-emitted file still shadows lower layers. Honors OCI whiteouts. Concurrency-safe (a cancelled scan
// can read via inFinal while this still writes).
func (fi *FinalIndex) apply(label string, idx int, name string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.degraded[label] {
		return
	}
	fi.labels[label] = true
	clean := path.Clean("/" + name)
	base := path.Base(clean)
	switch {
	case base == ".wh..wh..opq": // opaque: hide everything from lower layers under this dir
		fi.sweepSubtree(label, path.Dir(clean), idx)
	case strings.HasPrefix(base, ".wh."): // plain whiteout of dir/<name> — file OR whole dir subtree
		t := strings.TrimPrefix(base, ".wh.")
		if t == "" { // malformed ".wh." with no target — ignore, else it would sweep the whole parent dir
			return
		}
		target := path.Join(path.Dir(clean), t)
		delete(fi.owner, finalKey(label, target))
		fi.sweepSubtree(label, target, idx)
	default:
		if len(fi.owner) >= finalIndexMaxPaths {
			fi.markDegraded(label, "too many paths")
			return
		}
		fi.owner[finalKey(label, clean)] = idx // last-writer-wins
	}
}

// markDegraded gives up flatten tracking (in_final_image becomes unknown) and warns once. Caller holds mu.
func (fi *FinalIndex) markDegraded(label, reason string) {
	if !fi.degraded[label] {
		fi.degraded[label] = true
		logx.Warn("image flatten index degraded — in_final_image unavailable for this image", "label", label, "reason", reason)
	}
}

// sweepSubtree deletes every owner key under dir/ written below maxIdx, charging the work against the DoS
// budget. Caller holds mu.
func (fi *FinalIndex) sweepSubtree(label, dir string, maxIdx int) {
	fi.sweepWork[label] += len(fi.owner)
	if fi.sweepWork[label] > finalIndexMaxSweepWork {
		fi.markDegraded(label, "whiteout sweep budget exceeded")
		return
	}
	prefix := dir
	if prefix != "/" {
		prefix += "/"
	}
	keyPrefix := finalKey(label, prefix)
	for k, li := range fi.owner {
		if li < maxIdx && strings.HasPrefix(k, keyPrefix) {
			delete(fi.owner, k)
		}
	}
}

func (fi *FinalIndex) markAborted() { fi.mu.Lock(); fi.aborted = true; fi.mu.Unlock() }

// Aborted reports whether the layer walk was cut short (anti-bomb budget trip or ctx-cancel) — the scan
// is INCOMPLETE, so the caller must fail closed rather than certify the image clean. (degraded is not
// aborted: there the scan finished, only the in_final attribution is unavailable.)
func (fi *FinalIndex) Aborted() bool {
	if fi == nil {
		return false
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return fi.aborted
}

// inFinal reports (survives, known). A finding's file was always apply()'d in its own layer, so an absent
// key means a later layer whiteouted it = not in final (known false), not "unknown" — but only if this
// index actually folded that label. A foreign label / aborted / degraded index is genuinely unknown.
func (fi *FinalIndex) inFinal(label string, idx int, clean string) (bool, bool) {
	if fi == nil {
		return false, false
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.aborted || fi.degraded[label] || !fi.labels[label] {
		return false, false
	}
	li, ok := fi.owner[finalKey(label, clean)]
	return ok && li == idx, true
}

// buildInstructions maps each non-empty layer (1:1 with img.Layers()) to its Dockerfile instruction.
// Returns nil if history doesn't line up — a wrong attribution is worse than none.
func buildInstructions(cfg *v1.ConfigFile, nLayers int) []string {
	if cfg == nil {
		return nil
	}
	var ins []string
	for _, h := range cfg.History {
		if !h.EmptyLayer { // empty-layer entries (ENV/WORKDIR/…) consume no layer
			ins = append(ins, cleanInstruction(h.CreatedBy))
		}
	}
	if len(ins) != nLayers {
		return nil
	}
	return ins
}

// MarkFinalImage sets InFinalImage on each image finding by matching its Path against the flatten
// indexes. Config findings and unknown verdicts stay nil (never downgraded).
func MarkFinalImage(findings []model.Finding, indexes []*FinalIndex) []model.Finding {
	for i := range findings {
		label, idx, name, ok := parseLayerPath(findings[i].Path)
		if !ok {
			continue
		}
		clean := path.Clean("/" + name)
		for _, fi := range indexes {
			if final, known := fi.inFinal(label, idx, clean); known {
				v := final
				findings[i].InFinalImage = &v
				break
			}
		}
	}
	return findings
}

// parseLayerPath splits "label|layerN:name" into parts; ok=false for config/non-layer paths.
func parseLayerPath(p string) (label string, idx int, name string, ok bool) {
	bar := strings.IndexByte(p, '|')
	if bar < 0 {
		return "", 0, "", false
	}
	label, rest := p[:bar], p[bar+1:]
	if !strings.HasPrefix(rest, "layer") {
		return "", 0, "", false
	}
	rest = rest[len("layer"):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return "", 0, "", false
	}
	n, err := strconv.Atoi(rest[:colon])
	if err != nil {
		return "", 0, "", false
	}
	return label, n, rest[colon+1:], true
}

// imageLabel builds the per-image Path prefix; multi-image inputs (multi-arch index / multi-tag tar) get
// a #idx suffix so findings stay distinct.
func imageLabel(arg string, i, n int) string {
	l := strings.ReplaceAll(arg, "|", "_")
	if n > 1 {
		l = fmt.Sprintf("%s#%d", l, i)
	}
	return l
}

// emitImage emits the image config then walks every layer's tar in order, charging the shared anti-bomb
// budget and folding each layer into the flatten index fi.
func emitImage(ctx context.Context, ch chan<- model.Item, img v1.Image, label string, maxBytes int64, exclude []string, budget *imageBudget, fi *FinalIndex) {
	if !emitConfig(ctx, ch, img, label, maxBytes, budget) {
		return
	}
	layers, err := img.Layers()
	if err != nil {
		logx.Error("cannot read image layers", "err", err)
		return
	}
	if len(layers) > maxImageLayers { // reject an absurd layer count before reading any layer
		logx.Error("image extraction aborted: too many layers (possible decompression bomb)",
			"layers", len(layers), "limit", maxImageLayers)
		return
	}
	cfg, _ := img.ConfigFile()
	instructions := buildInstructions(cfg, len(layers)) // nil if history doesn't line up
	for i, layer := range layers {
		if ctx.Err() != nil {
			return
		}
		ins := ""
		if i < len(instructions) {
			ins = instructions[i]
		}
		if !emitLayer(ctx, ch, label, i, layer, maxBytes, exclude, budget, fi, ins) {
			return // ctx-cancel or budget abort; Image() logs budget.err
		}
	}
}

// emitConfig emits every secret-bearing config field plus each build-history instruction as its own Item
// (the prime non-filesystem secret locations). Returns false if the consumer asked to stop.
func emitConfig(ctx context.Context, ch chan<- model.Item, img v1.Image, label string, maxBytes int64, budget *imageBudget) bool {
	cfg, err := img.ConfigFile()
	if err != nil || cfg == nil {
		if err != nil {
			logx.Warn("cannot read image config", "err", err)
		}
		return true
	}
	c := cfg.Config
	emit := func(name, text string) bool {
		if text == "" || int64(len(text)) > maxBytes { // skip empty / oversized (a crafted multi-MB Env)
			return true
		}
		if !budget.addEntry(int64(len(text))) { // charge config against the same anti-bomb budget as layers
			return false
		}
		return send(ctx, ch, model.Item{Text: text, Source: "code", Path: label + "|image:config/" + name})
	}
	if !emit("env", strings.Join(c.Env, "\n")) || !emit("labels", joinLabels(c.Labels)) ||
		!emit("entrypoint", strings.Join(c.Entrypoint, " ")) || !emit("cmd", strings.Join(c.Cmd, " ")) ||
		!emit("onbuild", strings.Join(c.OnBuild, "\n")) || !emit("user", c.User) ||
		!emit("workingdir", c.WorkingDir) || !emit("stopsignal", c.StopSignal) {
		return false
	}
	if c.Healthcheck != nil && !emit("healthcheck", strings.Join(c.Healthcheck.Test, " ")) {
		return false
	}
	for n, h := range cfg.History { // each instruction separately keeps per-step provenance + fingerprints
		cb := cleanInstruction(h.CreatedBy)
		if cb == "" || int64(len(cb)) > maxBytes {
			continue
		}
		if !budget.addEntry(int64(len(cb))) {
			return false
		}
		if !send(ctx, ch, model.Item{Text: cb, Source: "code", Path: fmt.Sprintf("%s|image:config/history/%d", label, n)}) {
			return false
		}
	}
	return true
}

// cleanInstruction strips the buildkit "/bin/sh -c #(nop) " noise from a history CreatedBy for readability.
func cleanInstruction(s string) string {
	s = strings.TrimPrefix(s, "/bin/sh -c #(nop) ")
	s = strings.TrimPrefix(s, "/bin/sh -c ")
	return strings.TrimSpace(s)
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
func emitLayer(ctx context.Context, ch chan<- model.Item, label string, idx int, layer v1.Layer, maxBytes int64, exclude []string, b *imageBudget, fi *FinalIndex, instruction string) bool {
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
		fi.apply(label, idx, hdr.Name) // fold EVERY header (incl. whiteouts) before per-entry filtering
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
		it := model.Item{
			Text:   string(text),
			Source: "code",
			Path:   fmt.Sprintf("%s|layer%d:%s", label, idx, hdr.Name),
		}
		if instruction != "" {
			it.Meta = map[string]any{"instruction": instruction}
		}
		if !send(ctx, ch, it) {
			return false
		}
	}
}
