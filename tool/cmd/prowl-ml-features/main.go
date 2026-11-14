// prowl-ml-features extracts the canonical inference features for offline training.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Lercas/prowl/tool/internal/mlfeatures"
)

func run(in io.Reader, out io.Writer, names bool) error {
	enc := json.NewEncoder(out)
	if names {
		return enc.Encode(mlfeatures.FeatureNames)
	}
	dec := json.NewDecoder(in)
	for row := 1; ; row++ {
		var record struct {
			Value   string             `json:"value"`
			Context mlfeatures.Context `json:"context"`
		}
		if err := dec.Decode(&record); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("invalid training record %d", row)
		}
		if err := enc.Encode(mlfeatures.Extract(record.Value, record.Context)); err != nil {
			return fmt.Errorf("write training features: %w", err)
		}
	}
}

func main() {
	if len(os.Args) > 2 || (len(os.Args) == 2 && os.Args[1] != "--names") {
		fmt.Fprintln(os.Stderr, "usage: prowl-ml-features [--names] < corpus.jsonl")
		os.Exit(2)
	}
	if err := run(os.Stdin, os.Stdout, len(os.Args) == 2); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
