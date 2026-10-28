package main

import (
	"os"
	"path/filepath"
	"strings"
)

// normalizeScanArgs adds the local scan command only when the intent is unambiguous.
// Explicit commands always win, even if a same-named file exists in the workspace.
func normalizeScanArgs(args []string) []string {
	if len(args) == 0 {
		return []string{"scan"}
	}
	first := args[0]
	for _, command := range commands {
		if first == command.name {
			return args
		}
	}
	switch first {
	case "-h", "--help", "-V", "--version":
		return args
	}
	local := strings.HasPrefix(first, "-") || filepath.IsAbs(first) ||
		strings.HasPrefix(first, "./") || strings.HasPrefix(first, "../") ||
		strings.HasPrefix(first, `.\`) || strings.HasPrefix(first, `..\`)
	if !local && !strings.Contains(first, "://") {
		_, err := os.Stat(first) // #nosec G703 -- This local CLI explicitly accepts operator-selected paths.
		local = err == nil
	}
	if local {
		return append([]string{"scan"}, args...)
	}
	return args
}
