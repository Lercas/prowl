package source

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestStdinAPIDefaultBudgetMatchesReleasedContract(t *testing.T) {
	data := strings.Repeat("x", (4<<20)+1)
	for _, mode := range []string{"stdin", "named", "limited-zero", "limited-negative"} {
		t.Run(mode, func(t *testing.T) {
			input, err := os.CreateTemp(t.TempDir(), "owned-input-")
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err = input.WriteString(data); err != nil {
				t.Fatal(err)
			}
			if _, err = input.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			before := os.Stdin
			os.Stdin = input
			defer func() { os.Stdin = before }()
			coverage := model.NewCoverage()
			ctx := model.WithCoverage(t.Context(), coverage)
			var items []model.Item
			switch mode {
			case "stdin":
				items = archiveItems(Stdin(ctx))
			case "named":
				items = archiveItems(StdinNamed(ctx, "unopened/owned.txt"))
			case "limited-zero":
				items = archiveItems(StdinLimited(ctx, 0))
			case "limited-negative":
				items = archiveItems(StdinLimited(ctx, -1))
			}
			if len(items) != 1 || !errors.Is(items[0].Error, errSourceTooLarge) {
				t.Fatalf("released 4 MiB default not enforced: items=%d", len(items))
			}
			complete, _, _ := coverage.Snapshot()
			if complete {
				t.Fatal("oversize stdin certified complete")
			}
		})
	}
}

func TestStdinAPIOptionalAndExplicitLimits(t *testing.T) {
	data := strings.Repeat("x", (4<<20)+1)
	for _, mode := range []string{"optional", "named", "limited", "zero", "negative"} {
		t.Run(mode, func(t *testing.T) {
			input, err := os.CreateTemp(t.TempDir(), "owned-input-")
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err = input.WriteString(data); err != nil {
				t.Fatal(err)
			}
			if _, err = input.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			before := os.Stdin
			os.Stdin = input
			defer func() { os.Stdin = before }()
			coverage := model.NewCoverage()
			ctx := model.WithCoverage(t.Context(), coverage)
			var items []model.Item
			switch mode {
			case "optional":
				items = archiveItems(Stdin(ctx, 5<<20))
			case "named":
				items = archiveItems(StdinNamed(ctx, "unopened/owned.txt", 5<<20))
			case "limited":
				items = archiveItems(StdinLimited(ctx, 5<<20))
			case "zero":
				items = archiveItems(Stdin(ctx, 0))
			case "negative":
				items = archiveItems(Stdin(ctx, -1))
			}
			if len(items) != 1 {
				t.Fatal("stdin lost its single carrier", len(items))
			}
			if mode == "zero" || mode == "negative" {
				if !errors.Is(items[0].Error, errSourceTooLarge) {
					t.Fatal("nonpositive optional cap lost released default")
				}
			} else if items[0].Error != nil || items[0].Text != data {
				t.Fatal("explicit stdin cap ignored", items[0].Error)
			}
			complete, _, _ := coverage.Snapshot()
			if complete == (mode == "zero" || mode == "negative") {
				t.Fatal("stdin coverage disagrees with byte cap")
			}
		})
	}
}
