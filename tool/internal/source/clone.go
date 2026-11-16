package source

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Lercas/prowl/tool/internal/resilience"
)

const DefaultFetchTimeout = 5 * time.Minute

var legacyFetchTimeout atomic.Int64

func init() { legacyFetchTimeout.Store(int64(DefaultFetchTimeout)) }

// SetCloneTimeout changes defaults for future legacy source acquisitions.
func SetCloneTimeout(d time.Duration) {
	if d > 0 {
		legacyFetchTimeout.Store(int64(d))
	}
}

type fetchTimeoutKey struct{}

// WithFetchTimeout selects one acquisition's default, independent of legacy setters.
// An explicit per-operation timeout still takes priority.
func WithFetchTimeout(ctx context.Context, d time.Duration) context.Context {
	if d <= 0 {
		d = DefaultFetchTimeout
	}
	return context.WithValue(ctx, fetchTimeoutKey{}, d)
}
func snapshotFetchTimeout(ctx context.Context) context.Context {
	if _, ok := ctx.Value(fetchTimeoutKey{}).(time.Duration); ok {
		return ctx
	}
	return WithFetchTimeout(ctx, time.Duration(legacyFetchTimeout.Load()))
}
func contextFetchTimeout(ctx context.Context, explicit time.Duration) time.Duration {
	if explicit > 0 {
		return explicit
	}
	if d, ok := ctx.Value(fetchTimeoutKey{}).(time.Duration); ok {
		return d
	}
	return time.Duration(legacyFetchTimeout.Load())
}

// CloneOpts configures a repository clone for scanning.
type CloneOpts struct {
	URL     string
	Branch  string        // clone a single branch/tag (default: the remote's default branch)
	Full    bool          // full history (needed for --history); default is a shallow depth-1 clone
	Depth   int           // shallow depth override (0 = 1 when !Full)
	Timeout time.Duration // per-attempt clone deadline (0 = acquisition default)
}

// CloneRepo clones a git repository into a temp directory for scanning, disabling the ext/file remote
// helpers (which turn a clone URL into command execution) and accepting only https/http/ssh/scp
// transports. Returns the checkout dir and a cleanup func. Retried for transient failures, each attempt
// bounded by its own timeout; ctx cancellation aborts immediately and is never retried.
func CloneRepo(ctx context.Context, o CloneOpts) (dir string, cleanup func(), err error) {
	ctx = snapshotFetchTimeout(ctx)
	noop := func() {}
	if !isCloneURL(o.URL) {
		return "", noop, errors.New("unsupported repo URL (use https://, ssh://, or git@host:path)")
	}
	tmp, err := os.MkdirTemp("", "prowl-repo-*")
	if err != nil {
		return "", noop, err
	}
	cleanup = func() { os.RemoveAll(tmp) }

	args := []string{
		"-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=user",
		"clone", "--quiet",
	}
	if o.Full && o.Branch == "" {
		args = append(args, "--tags")
	} else {
		args = append(args, "--no-tags")
	}
	if !o.Full {
		depth := o.Depth
		if depth <= 0 {
			depth = 1
		}
		args = append(args, "--depth", strconv.Itoa(depth))
	}
	if o.Branch != "" {
		args = append(args, "--branch", o.Branch, "--single-branch")
	}
	args = append(args, "--", o.URL, tmp) // "--" stops the URL being parsed as a flag

	perAttempt := contextFetchTimeout(ctx, o.Timeout)
	runErr := resilience.Retry(ctx, 3, 500*time.Millisecond, 5*time.Second, func() error {
		// Each retry starts from a clean target dir: `git clone` refuses a non-empty destination, and a
		// failed attempt can leave a partial tree behind.
		if err := resetDir(tmp); err != nil {
			return err
		}
		actx, cancel := context.WithTimeout(ctx, perAttempt)
		defer cancel()
		cmd := exec.CommandContext(actx, "git", args...)
		_, err := runOwnedCommand(cmd)
		if err != nil {
			if ctx.Err() != nil { // parent cancelled (Ctrl-C / overall --timeout): give up, don't retry
				return ctx.Err()
			}
			if actx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("git clone timed out after %s: %w", perAttempt, context.DeadlineExceeded)
			}
			return &cloneFailure{cause: err}
		}
		return nil
	})
	if runErr != nil {
		cleanup()
		return "", noop, runErr
	}
	return tmp, cleanup, nil
}

// cloneFailure keeps command/provider-controlled diagnostics out of logs and reports. Git helpers
// can print credentials separately from the input URL, so replacing the URL alone is insufficient.
// Keep the original cause for callers that classify startup, exit, or pipe-wait failures.
type cloneFailure struct{ cause error }

func (e *cloneFailure) Error() string {
	var exit *exec.ExitError
	if errors.As(e.cause, &exit) {
		if code := exit.ExitCode(); code >= 0 {
			return fmt.Sprintf("git clone failed (exit status %d)", code)
		}
		return "git clone failed (terminated by signal)"
	}
	var start *exec.Error
	if errors.As(e.cause, &start) {
		return "git clone could not be started"
	}
	return "git clone failed"
}

func (e *cloneFailure) Unwrap() error { return e.cause }

// resetDir empties dir by removing and recreating it (so a retried clone sees an empty destination).
func resetDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.MkdirAll(dir, 0o700)
}

// isCloneURL accepts only explicit, non-RCE transports (a bare ".git" suffix would let "ext::sh -c ..."
// through). http:// is allowed here (unlike `rules update`): it's a read-only scan target, not executable rules.
func isCloneURL(s string) bool {
	for _, p := range []string{"https://", "http://", "ssh://", "git://"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return strings.HasPrefix(s, "git@") && strings.Contains(s, ":") // scp-like git@host:path
}
