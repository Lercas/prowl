package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Lercas/prowl/tool/internal/correlation"
)

func cmdCorrelate(args []string) int {
	_, rest, err := parseCommand("correlate", args)
	if err != nil {
		return commandParseError(err)
	}
	args = rest
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Использование: prowl correlate REPORT.json REPORT.json [...]")
		return 2
	}
	if len(args) > 32 {
		fmt.Fprintln(os.Stderr, "Не более 32 отчётов за один запуск")
		return 2
	}
	reports, err := correlation.ReadMany(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Сопоставление:", err)
		return 2
	}
	result, err := correlation.Join(reports)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return 2
	}
	if !result.Complete {
		return 2
	}
	return 0
}
func cmdRemediation(args []string) int {
	_, rest, err := parseCommand("remediation-check", args)
	if err != nil {
		return commandParseError(err)
	}
	args = rest
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "Использование: prowl remediation-check BEFORE.json AFTER.json")
		return 2
	}
	reports, err := correlation.ReadMany(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	b, a := reports[0], reports[1]
	r, err := correlation.Compare(b, a)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		return 2
	}
	if !r.Comparable || !r.Complete {
		return 2
	}
	for _, x := range r.Items {
		if x.Presence == "present" {
			return 1
		}
	}
	return 0
}
