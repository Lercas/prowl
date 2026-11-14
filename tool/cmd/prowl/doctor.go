package main

import (
	"fmt"
	"os"

	"github.com/Lercas/prowl/tool/internal/doctor"
	"github.com/Lercas/prowl/tool/internal/logx"
)

func cmdDoctor(args []string) int {
	c, _, err := parseCommand("doctor", args)
	if err != nil {
		return commandParseError(err)
	}
	if code := rejectUnsupportedOCR(c, "doctor"); code != 0 {
		return code
	}
	setupLogging(c)
	cfg, err := loadConfig(&c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}
	det, tax, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}
	checks := doctor.Run(det, tax, cfg)
	color := !c.noColor && os.Getenv("NO_COLOR") == "" && isTTY(os.Stdout)
	fmt.Println("prowl doctor")
	for _, ch := range checks {
		fmt.Println(doctorLine(ch, color))
	}
	if doctor.Healthy(checks) {
		fmt.Println("\nall checks passed — scanner is healthy")
		return 0
	}
	fmt.Println("\nFAILED — one or more checks did not pass (see ✗ above)")
	return 1
}

func doctorLine(ch doctor.Check, color bool) string {
	sym, col := "✓", "\x1b[32m"
	switch ch.Status {
	case doctor.StatusWarn:
		sym, col = "!", "\x1b[33m"
	case doctor.StatusFail:
		sym, col = "✗", "\x1b[31m"
	}
	if color {
		sym = col + sym + "\x1b[0m"
	}
	return fmt.Sprintf("  %s %-26s %s", sym, ch.Name, ch.Detail)
}
