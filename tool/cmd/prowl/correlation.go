package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Lercas/prowl/tool/internal/correlation"
	"github.com/Lercas/prowl/tool/internal/model"
)

func cmdCorrelate(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Использование: prowl correlate REPORT.json REPORT.json [...]")
		return 2
	}
	if len(args) > 32 {
		fmt.Fprintln(os.Stderr, "Не более 32 отчётов за один запуск")
		return 2
	}
	var total int64
	for _, p := range args {
		if info, err := os.Stat(p); err == nil { // #nosec G703 -- read-only size check on the explicitly selected report
			total += info.Size()
		}
	}
	if total > 128<<20 {
		fmt.Fprintln(os.Stderr, "Суммарный объём отчётов превышает 128 MiB")
		return 2
	}
	var reports []model.ScanResult
	for _, p := range args {
		r, err := correlation.Read(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Сопоставление:", err)
			return 2
		}
		reports = append(reports, r)
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
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "Использование: prowl remediation-check BEFORE.json AFTER.json")
		return 2
	}
	b, err := correlation.Read(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	a, err := correlation.Read(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
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
