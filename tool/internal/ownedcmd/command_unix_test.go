//go:build unix

package ownedcmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestOwnedTreeHelper(t *testing.T) {
	role := os.Getenv("PROWL_OWNEDCMD_TREE_ROLE")
	if role == "" {
		return
	}
	if role == "parent" {
		child := exec.Command(os.Args[0], "-test.run=^TestOwnedTreeHelper$")
		child.Env = append(os.Environ(), "PROWL_OWNEDCMD_TREE_ROLE=child")
		inherited := os.NewFile(3, "descendant lifetime")
		child.ExtraFiles = []*os.File{inherited}
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		_ = inherited.Close()
		ready := os.NewFile(4, "tree ready")
		_, _ = fmt.Fprintf(ready, "%d %d\n", os.Getpid(), child.Process.Pid)
		_ = ready.Close()
		_ = child.Wait()
		os.Exit(0)
	}
	// The descendant holds descriptor 3 open until it dies. The test observes
	// EOF on this independent pipe, so killing only the direct parent cannot pass.
	time.Sleep(time.Minute)
	os.Exit(0)
}

func TestCancellationStopsOwnedDescendants(t *testing.T) {
	lifetime, held, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer lifetime.Close()
	defer held.Close()
	ready, announce, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	defer announce.Close()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-test.run=^TestOwnedTreeHelper$")
	cmd.Env = append(os.Environ(), "PROWL_OWNEDCMD_TREE_ROLE=parent")
	cmd.ExtraFiles = []*os.File{held, announce}
	finished := make(chan error, 1)
	done := make(chan struct{})
	go func() { _, err := Run(cmd); finished <- err; close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned command cleanup timed out")
		}
	}()
	if err := ready.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(ready).ReadString('\n')
	if err != nil {
		t.Fatalf("owned process tree did not start: %v", err)
	}
	var parent, child int
	if _, err := fmt.Fscan(strings.NewReader(line), &parent, &child); err != nil {
		t.Fatal(err)
	}
	if group, err := syscall.Getpgid(child); err != nil || group != parent {
		t.Fatalf("descendant escaped owned process group: group=%d parent=%d err=%v", group, parent, err)
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("cancelled process tree reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owned parent did not stop")
	}
	// Wait for Run to stop reading ExtraFiles before closing the local copies.
	_ = held.Close()
	_ = announce.Close()
	if err := lifetime.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := lifetime.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("descendant survived parent cancellation: %v", err)
	}
}
