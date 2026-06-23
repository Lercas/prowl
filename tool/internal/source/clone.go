package source

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/resilience"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// defaultFetchTimeout bounds a single remote-fetch attempt (clone / image pull / bucket sync) when
// --timeout is unset. Overridable via config (limits.clone_timeout); set once at startup.
var defaultFetchTimeout = 5 * time.Minute

// SetCloneTimeout overrides the default per-attempt fetch deadline; a non-positive value is ignored.
func SetCloneTimeout(d time.Duration) {
	if d > 0 {
		defaultFetchTimeout = d
	}
}

// fetchTimeout returns the per-attempt deadline: the user's --timeout when set, else the default.
func fetchTimeout(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return defaultFetchTimeout
}

// CloneOpts configures a repository clone for scanning.
type CloneOpts struct {
	URL     string
	Branch  string        // clone a single branch/tag (default: the remote's default branch)
	Full    bool          // full history (needed for --history); default is a shallow depth-1 clone
	Depth   int           // shallow depth override (0 = 1 when !Full)
	Timeout time.Duration // per-attempt clone deadline (0 = defaultFetchTimeout)
}

// CloneRepo clones a git repository into a temp directory for scanning, disabling the ext/file remote
// helpers (which turn a clone URL into command execution) and accepting only https/http/ssh/scp
// transports. Returns the checkout dir and a cleanup func. Retried for transient failures, each attempt
// bounded by its own timeout; ctx cancellation aborts immediately and is never retried.
func CloneRepo(ctx context.Context, o CloneOpts) (dir string, cleanup func(), err error) {
	noop := func() {}
	if !isCloneURL(o.URL) {
		return "", noop, fmt.Errorf("unsupported repo URL %q (use https://, ssh://, or git@host:path)", safehttp.RedactURL(o.URL))
	}
	tmp, err := os.MkdirTemp("", "prowl-repo-*")
	if err != nil {
		return "", noop, err
	}
	cleanup = func() { os.RemoveAll(tmp) }

	args := []string{
		"-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=user",
		"clone", "--quiet", "--no-tags",
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

	perAttempt := fetchTimeout(o.Timeout)
	runErr := resilience.Retry(ctx, 3, 500*time.Millisecond, 5*time.Second, func() error {
		// Each retry starts from a clean target dir: `git clone` refuses a non-empty destination, and a
		// failed attempt can leave a partial tree behind.
		if err := resetDir(tmp); err != nil {
			return err
		}
		actx, cancel := context.WithTimeout(ctx, perAttempt)
		defer cancel()
		cmd := exec.CommandContext(actx, "git", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if ctx.Err() != nil { // parent cancelled (Ctrl-C / overall --timeout): give up, don't retry
				return ctx.Err()
			}
			if actx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("git clone timed out after %s", perAttempt)
			}
			return fmt.Errorf("git clone failed: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	})
	if runErr != nil {
		cleanup()
		return "", noop, runErr
	}
	return tmp, cleanup, nil
}

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
