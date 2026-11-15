package source

import (
	"os/exec"
	"strings"
	"testing"
)

func TestChangedFilesErrorNamesTheCause(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	_, err := GitChangedFilesIn(t.Context(), dir, "since", "no-such-revision")
	if err == nil || !strings.Contains(err.Error(), "no-such-revision") {
		t.Fatalf("an unknown revision was reported without naming it: %v", err)
	}
}
