package source

import (
	"github.com/Lercas/prowl/tool/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func agentWrite(t *testing.T, root, path, text string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	write(t, full, text)
}

func TestAgentSurfaceSelectsConfigsTranscriptsAndExplicitHistory(t *testing.T) {
	project, home := t.TempDir(), t.TempDir()
	for _, path := range []string{".mcp.json", ".claude/projects/owned/a.jsonl", ".cursor/rules/a.mdc", "ordinary.env"} {
		agentWrite(t, project, path, "AWS=AKIANAFGYOEYPXU1DSYP\n")
	}
	agentWrite(t, home, ".codex/sessions/a.jsonl", "AWS=AKIANAFGYOEYPXU1DSYP\n")
	agentWrite(t, home, ".bash_history", "AWS=AKIANAFGYOEYPXU1DSYP\n")
	for _, history := range []bool{false, true} {
		count, transcripts, histories := 0, 0, 0
		for item := range AgentSurface(t.Context(), AgentOptions{Projects: []string{project}, Home: home, ShellHistory: history, MaxBytes: 1024}) {
			if item.Error != nil {
				t.Fatal(item.Error)
			}
			if item.Agent == nil || strings.HasSuffix(item.Path, "ordinary.env") {
				t.Fatal("untargeted source or missing provenance")
			}
			count++
			if item.Agent.Kind == "transcript" {
				transcripts++
			}
			if item.Agent.Kind == "history" {
				histories++
			}
		}
		expected := 4
		if history {
			expected++
		}
		if count != expected || transcripts != 2 || histories != expected-4 {
			t.Fatal("agent surface selection changed")
		}
	}
	count := 0
	for item := range AgentSurface(t.Context(), AgentOptions{Projects: []string{project}, MaxBytes: 1024}) {
		if item.Error != nil {
			t.Fatal(item.Error)
		}
		count++
		if strings.HasPrefix(item.Path, home) {
			t.Fatal("home scanned without opt-in")
		}
	}
	if count != 3 {
		t.Fatal("project target selection failed")
	}
}

func TestAgentSurfaceErrorsDoNotBecomeClean(t *testing.T) {
	root := t.TempDir()
	agentWrite(t, root, ".mcp.json", "long config payload")
	errorsSeen := 0
	for item := range AgentSurface(t.Context(), AgentOptions{Projects: []string{root, filepath.Join(root, "missing")}, MaxBytes: 3}) {
		if item.Error != nil {
			errorsSeen++
		}
	}
	if errorsSeen != 2 {
		t.Fatal("unreadable/oversized source lost diagnostics")
	}
	agentWrite(t, root, ".mcp.json", "\x00\x01\x02\x03")
	for item := range AgentSurface(t.Context(), AgentOptions{Projects: []string{root}, MaxBytes: 1024}) {
		if item.Error == nil {
			t.Fatal("binary config reported as inspected text")
		}
	}
}

func TestAgentSurfaceDoesNotFollowDiscoveredSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	agentWrite(t, outside, "owned.json", "AWS=AKIANAFGYOEYPXU1DSYP")
	if err := os.Symlink(outside, filepath.Join(root, ".cursor")); err != nil {
		t.Skip("symlink unavailable")
	}
	diagnostic := false
	for item := range AgentSurface(t.Context(), AgentOptions{Projects: []string{root}, MaxBytes: 1024}) {
		if item.Error == nil {
			t.Fatal("discovered link was followed")
		}
		diagnostic = true
	}
	if !diagnostic {
		t.Fatal("uninspected link not reported")
	}
}

func TestAgentSurfaceFileBudgetFailsClosedBeforeReading(t *testing.T) {
	root := t.TempDir()
	agentWrite(t, root, ".mcp.json", "AWS=AKIANAFGYOEYPXU1DSYP")
	items := make(chan model.Item, 2)
	budget := 0
	if walkAgentRoot(t.Context(), items, root, projectAgentTargets, AgentOptions{MaxBytes: 1024}, &budget, map[string]bool{}) {
		t.Fatal("exhausted file budget continued")
	}
	close(items)
	diagnostics := 0
	for item := range items {
		if item.Error == nil || item.Text != "" {
			t.Fatal("file read after budget exhausted")
		}
		diagnostics++
	}
	if diagnostics != 1 {
		t.Fatal("file budget did not report incomplete source")
	}
}
