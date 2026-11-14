package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

func (c *commonFlags) scanPreflight() int {
	if code := c.mlPreflight(); code != 0 {
		return code
	}
	if c.indexDir == "" {
		return 0
	}
	if err := validateIndexOutputs(*c); err != nil {
		return indexError(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store, err := secretindex.Open(ctx, c.indexDir, false)
	if err != nil {
		return indexError(err)
	}
	if err := store.Close(); err != nil {
		return indexError(err)
	}
	return 0
}

func recordIndexedScan(ctx context.Context, c commonFlags, findings []model.Finding) (err error) {
	if err := validateIndexOutputs(c); err != nil {
		return err
	}
	store, err := secretindex.Open(ctx, c.indexDir, false)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	complete := ctx.Err() == nil && model.NewResult(nil, c.coverage).Complete
	if c.indexCoverageComplete != nil {
		complete = complete && c.indexCoverageComplete()
	}
	if c.indexEvidence != nil {
		findings = append(append([]model.Finding(nil), findings...), c.indexEvidence.snapshot()...)
	}
	id, err := store.Record(ctx, c.indexScope, time.Now().UTC(), complete, findings)
	if err == nil {
		logx.Info("скан записан в локальный индекс", "scan_id", id, "scope", c.indexScope)
	}
	return err
}

func cmdIndex(command string, args []string) int {
	c, rest, err := parseCommand(command, args)
	if err != nil {
		return commandParseError(err)
	}
	if err := validateIndexOutputs(c); err != nil {
		return indexError(err)
	}
	if command == "index" && len(rest) != 0 {
		return commandParseError(errors.New("index не принимает позиционные аргументы"))
	}
	if command == "diff" && len(rest) != 0 && len(rest) != 2 {
		return commandParseError(errors.New("diff принимает два ID сканов или --scope для последних двух сканов"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := secretindex.Open(ctx, c.indexDir, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "индекс:", err)
		return 2
	}
	defer store.Close()
	var payload any
	if command == "index" {
		scans, err := store.Scans(ctx, c.indexScope)
		if err != nil {
			return indexError(err)
		}
		var through int64
		if len(scans) > 0 {
			through = scans[len(scans)-1].ID
		}
		secrets, err := store.SecretsThrough(ctx, c.indexScope, through)
		if err != nil {
			return indexError(err)
		}
		payload = indexView{scans, secrets}
	} else {
		var from, to int64
		if len(rest) == 2 {
			from, err = strconv.ParseInt(rest[0], 10, 64)
			if err != nil || from <= 0 {
				return indexError(errors.New("неверный ID первого скана"))
			}
			to, err = strconv.ParseInt(rest[1], 10, 64)
			if err != nil || to <= 0 {
				return indexError(errors.New("неверный ID второго скана"))
			}
		} else {
			if c.indexScope == "" {
				return indexError(errors.New("для автоматического diff требуется --scope NAME"))
			}
			scans, err := store.Scans(ctx, c.indexScope)
			if err != nil {
				return indexError(err)
			}
			if len(scans) < 2 {
				return indexError(errors.New("в области нет двух сканов"))
			}
			from, to = scans[len(scans)-2].ID, scans[len(scans)-1].ID
		}
		diff, err := store.Diff(ctx, from, to)
		if err != nil {
			return indexError(err)
		}
		if c.indexScope != "" && diff.From.Scope != c.indexScope {
			return indexError(errors.New("ID сканов не принадлежат указанной области"))
		}
		payload = diff
	}
	write := func(w io.Writer) error { return writeIndexPayload(w, payload, c.format) }
	if c.output != "" {
		err = localfile.WriteAtomic(c.output, 0o600, write)
	} else {
		err = write(os.Stdout)
	}
	if err != nil {
		return indexError(err)
	}
	return 0
}

func indexError(err error) int { fmt.Fprintln(os.Stderr, "индекс:", err); return 2 }

type indexEvidence struct {
	mu       sync.Mutex
	findings []model.Finding
}

func (e *indexEvidence) add(f model.Finding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.findings = append(e.findings, f)
}
func (e *indexEvidence) snapshot() []model.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]model.Finding(nil), e.findings...)
}

type indexView struct {
	Scans   []secretindex.Scan   `json:"scans"`
	Secrets []secretindex.Secret `json:"secrets"`
}

func writeIndexPayload(w io.Writer, payload any, format string) error {
	if format == "json" {
		return json.NewEncoder(indexReportWriter{w}).Encode(payload)
	}
	var b strings.Builder
	clean := logx.SanitizeTerminal
	label := func(id string) string {
		if len(id) > 16 {
			return id[len(id)-16:]
		}
		return clean(id)
	}
	switch value := payload.(type) {
	case indexView:
		fmt.Fprintf(&b, "Сканы: %d; секреты: %d\n", len(value.Scans), len(value.Secrets))
		for _, s := range value.Scans {
			state := "неполный"
			if s.Complete {
				state = "полный"
			}
			fmt.Fprintf(&b, "  Скан %d | %s | %s | %s\n", s.ID, clean(s.Scope), s.At.Format(time.RFC3339), state)
		}
		for _, s := range value.Secrets {
			fmt.Fprintf(&b, "\nСекрет %s | мест за историю: %d | последнее подтверждённое состояние: %s", label(s.ValueID), s.LocationCount, s.LastConfirmedState)
			if s.LastConfirmedAt != nil {
				fmt.Fprintf(&b, " (%s)", s.LastConfirmedAt.Format(time.RFC3339))
			}
			b.WriteByte('\n')
			for _, l := range s.Locations {
				fmt.Fprintf(&b, "  %s [%s] %s:%d:%d [%s]\n", clean(l.Source), clean(l.Scope), clean(l.Path), l.Line, l.Col, clean(l.Type))
			}
			for _, e := range s.Transitions {
				fmt.Fprintf(&b, "  %s → %s: %s", e.From, e.To, e.ObservedAt.Format(time.RFC3339))
				if e.SecondsSinceFirstLive != nil {
					fmt.Fprintf(&b, "; после первого live-наблюдения %.0f с", *e.SecondsSinceFirstLive)
				}
				b.WriteByte('\n')
			}
		}
	case secretindex.Diff:
		fmt.Fprintf(&b, "Сканы %d → %d | %s\nНовые секреты: %d\nНе наблюдались: %d\nНовые места: %d\nНе наблюдались в прежних местах: %d\n", value.From.ID, value.To.ID, clean(value.From.Scope), len(value.NewValues), len(value.NotSeenValues), len(value.NewLocations), len(value.NotSeenLocations))
		for _, id := range value.NewValues {
			fmt.Fprintf(&b, "  + секрет %s\n", label(id))
		}
		for _, id := range value.NotSeenValues {
			fmt.Fprintf(&b, "  ? секрет %s\n", label(id))
		}
		for _, l := range value.NewLocations {
			fmt.Fprintf(&b, "  + %s %s:%d:%d\n", label(l.ValueID), clean(l.Path), l.Line, l.Col)
		}
		for _, l := range value.NotSeenLocations {
			fmt.Fprintf(&b, "  ? %s %s:%d:%d\n", label(l.ValueID), clean(l.Path), l.Line, l.Col)
		}
		for _, v := range value.VerificationChanges {
			fmt.Fprintf(&b, "  %s: %s → %s\n", label(v.ValueID), v.From, v.To)
		}
	default:
		return errors.New("unsupported index report")
	}
	text := b.String()
	n, err := io.WriteString(w, text)
	if err == nil && n != len(text) {
		err = io.ErrShortWrite
	}
	return err
}

type indexReportWriter struct{ io.Writer }

func (w indexReportWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

func validateIndexOutputs(c commonFlags) error {
	if c.indexDir == "" {
		return nil
	}
	root, err := resolvedIndexPath(c.indexDir)
	if err != nil {
		return err
	}
	for _, output := range []string{c.output, c.writeBaseline} {
		if output == "" {
			continue
		}
		path, err := resolvedIndexPath(output)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err == nil && (rel == "." || filepath.IsLocal(rel)) {
			return errors.New("отчёт или baseline нельзя записывать внутрь каталога индекса")
		}
	}
	return nil
}

func resolvedIndexPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(abs)
		if err == nil {
			for n := len(tail) - 1; n >= 0; n-- {
				resolved = filepath.Join(resolved, tail[n])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", err
		}
		tail = append(tail, filepath.Base(abs))
		abs = parent
	}
}
