package main

import (
	"fmt"
	"os"

	"github.com/Lercas/prowl/tool/internal/config"
)

// cmdConfig handles `prowl config validate`: lint a .prowl.yaml for unknown/typo'd keys, empty or
// match-everything custom regexes, and unknown custom-rule categories. Exit 0 clean, 1 problems, 2 error.
func cmdConfig(args []string) int {
	if len(args) == 0 || args[0] != "validate" {
		fmt.Fprintln(os.Stderr, "usage: prowl config validate [FILE]   (default .prowl.yaml)")
		return 2
	}
	path := ".prowl.yaml"
	if len(args) > 1 {
		path = args[1]
	}
	problems, ioErr := config.ValidateFile(path)
	if ioErr != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", ioErr)
		return 2
	}
	if len(problems) == 0 {
		fmt.Printf("%s: ok\n", path)
		return 0
	}
	fmt.Fprintf(os.Stderr, "%s: %d problem(s)\n", path, len(problems))
	for _, p := range problems {
		fmt.Fprintf(os.Stderr, "  - %s\n", p)
	}
	return 1
}
