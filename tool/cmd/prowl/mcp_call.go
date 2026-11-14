package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/model"
)

func mcpCall(w *mcpWriter, req mcpRequest) { mcpCallContext(context.Background(), w, req) }
func mcpCallContext(ctx context.Context, w *mcpWriter, req mcpRequest, runners ...scanRunner) {
	var p struct {
		Name string         `json:"name"`
		Args map[string]any `json:"arguments"`
	}
	if err := jsonstrict.UnmarshalContext(ctx, req.Params, &p); err != nil || p.Name == "" {
		mcpError(w, req.ID, -32602, "invalid tool call parameters")
		return
	}
	known := false
	for _, tool := range mcpTools() {
		if tool.Name == p.Name {
			known = true
			break
		}
	}
	if !known {
		mcpError(w, req.ID, -32602, "unknown tool")
		return
	}
	argv, err := mcpArgv(p.Name, p.Args)
	if err != nil {
		mcpToolResult(w, req.ID, err.Error(), true)
		return
	}
	runner := scanRunner(runSelfContext)
	if len(runners) > 0 {
		runner = runners[0]
	}
	out, runErr := runner(ctx, argv)
	if errors.Is(runErr, errMCPOutputLimit) {
		mcpToolResult(w, req.ID, "Отчёт превышает лимит MCP (32 МиБ)", true)
		return
	}
	if strings.TrimSpace(out) == "" && runErr != nil {
		message := "Скан не запустился или завершился без отчёта; проверьте путь, настройки и доступ к источнику"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			message = "Превышен лимит времени сканирования (5 минут)"
		} else if errors.Is(ctx.Err(), context.Canceled) {
			message = "Сканирование отменено"
		}
		mcpToolResult(w, req.ID, message, true)
		return
	}
	var result model.ScanResult
	if jsonstrict.UnmarshalContext(context.Background(), []byte(out), &result) != nil || result.SchemaVersion != "1.4" || result.Findings == nil || result.Count != len(result.Findings) {
		mcpToolResult(w, req.ID, "Недопустимый ответ сканера", true)
		return
	}
	failed := !result.Complete || result.Truncated || model.NewResult(result.Findings, nil).Truncated
	if runErr != nil {
		var exit *exec.ExitError
		if !errors.As(runErr, &exit) || exit.ExitCode() != 1 || len(result.Findings) == 0 {
			failed = true
		}
	}
	mcpReply(w, req.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": out}}, "structuredContent": result, "isError": failed})
}

func runSelfContext(parent context.Context, argv []string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, argv...)
	cmd.WaitDelay = 2 * time.Second
	output := &boundedMCPOutput{cancel: cancel}
	cmd.Stdout = output
	err = cmd.Run()
	if output.exceeded {
		return "", errMCPOutputLimit
	}
	return output.String(), err
}

type boundedMCPOutput struct {
	bytes.Buffer
	cancel   context.CancelFunc
	exceeded bool
}

var errMCPOutputLimit = errors.New("MCP output budget exceeded")

func (w *boundedMCPOutput) Write(p []byte) (int, error) {
	if len(p)+w.Len() > 32<<20 {
		w.exceeded = true
		w.cancel()
		return 0, errMCPOutputLimit
	}
	return w.Buffer.Write(p)
}
