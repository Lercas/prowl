// Package ocr sends bounded document images to an explicitly enabled OCR/VLM endpoint.
package ocr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Lercas/prowl/tool/internal/safehttp"
)

const (
	DefaultURL    = "http://127.0.0.1:8080/v1/chat/completions"
	DefaultModel  = "mlx-community/Qwen3.6-27B-4bit"
	defaultPrompt = "Извлеки весь видимый текст с изображения. Сохрани точный регистр, пробелы, " +
		"переносы строк, цифры, пунктуацию и специальные символы. Не исправляй, не дополняй и не " +
		"маскируй ключи, токены, пароли или другие строки. Верни только распознанный текст без " +
		"комментариев и без Markdown-ограждений."
)

// Config controls the optional OCR backend. APIKey must come from an environment variable, not argv.
type Config struct {
	URL         string
	Model       string
	APIKey      string
	Prompt      string
	AllowRemote bool
	AllPDFPages bool
	MaxPDFPages int
	MaxImage    int64
	MaxOutput   int64
	MaxTokens   int
	ScaleTo     int
	Timeout     time.Duration
}

// Stats records whether OCR coverage was complete.
type Stats struct {
	Calls     int
	Failures  int
	Empty     int
	Skipped   int
	LastError string
}

// Engine combines the API client, PDF renderer, coverage limits, and failure accounting.
type Engine struct {
	cfg    Config
	client *client
	render renderFunc
	mu     sync.Mutex
	stats  Stats
}

type client struct {
	url       string
	model     string
	apiKey    string
	prompt    string
	maxOutput int64
	maxTokens int
	http      *http.Client
}

type renderFunc func(context.Context, []byte, int, int, int64) ([]byte, error)

// New creates an OCR engine. The default endpoint is loopback-only; a non-loopback endpoint requires
// AllowRemote and HTTPS so enabling OCR cannot silently exfiltrate documents.
func New(cfg Config) (*Engine, error) {
	cfg = defaults(cfg)
	endpoint, local, err := validateEndpoint(cfg.URL, cfg.AllowRemote)
	if err != nil {
		return nil, err
	}
	var httpClient *http.Client
	if local {
		httpClient = localHTTPClient(cfg.Timeout)
	} else {
		httpClient = safehttp.Client(cfg.Timeout)
	}
	return &Engine{
		cfg: cfg,
		client: &client{
			url: endpoint.String(), model: cfg.Model, apiKey: cfg.APIKey, prompt: cfg.Prompt,
			maxOutput: cfg.MaxOutput, maxTokens: cfg.MaxTokens, http: httpClient,
		},
		render: renderPDFPage,
	}, nil
}

func defaults(cfg Config) Config {
	if cfg.URL == "" {
		cfg.URL = DefaultURL
	}
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	if cfg.Prompt == "" {
		cfg.Prompt = defaultPrompt
	}
	if cfg.MaxPDFPages <= 0 {
		cfg.MaxPDFPages = 20
	}
	if cfg.MaxImage <= 0 {
		cfg.MaxImage = 20 << 20
	}
	if cfg.MaxOutput <= 0 {
		cfg.MaxOutput = 10 << 20
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 8192
	}
	if cfg.ScaleTo <= 0 {
		cfg.ScaleTo = 2048
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}
	return cfg
}

func validateEndpoint(raw string, allowRemote bool) (*url.URL, bool, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Hostname() == "" {
		return nil, false, fmt.Errorf("invalid OCR URL %q", safehttp.RedactURL(raw))
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, false, errors.New("OCR URL must not contain credentials, query, or fragment")
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, false, errors.New("OCR URL must use http or https")
	}
	local := isLoopbackHost(endpoint.Hostname())
	if !local && !allowRemote {
		return nil, false, errors.New("remote OCR URL requires --ocr-allow-remote (documents may contain secrets)")
	}
	if !local && endpoint.Scheme != "https" {
		return nil, false, errors.New("remote OCR URL must use HTTPS")
	}
	return endpoint, local, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func localHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, candidate := range addresses {
			if !candidate.IP.IsLoopback() {
				return nil, fmt.Errorf("OCR endpoint %q resolved outside loopback", host)
			}
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("OCR endpoint %q resolved to no addresses", host)
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
	}
	return &http.Client{
		Timeout: timeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("OCR endpoint redirects are disabled")
		},
	}
}

// MaybeImage reports extensions that may be sent to OCR. ExtractImage still verifies magic/MIME.
func MaybeImage(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".png", ".jpg", ".jpeg", ".webp"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// ExtractImage recognizes one PNG/JPEG/WebP payload.
func (e *Engine) ExtractImage(ctx context.Context, data []byte) (string, error) {
	if int64(len(data)) > e.cfg.MaxImage {
		err := fmt.Errorf("OCR image exceeds the %d-byte limit", e.cfg.MaxImage)
		e.failure(err)
		return "", err
	}
	mediaType, ok := imageMediaType(data)
	if !ok {
		err := errors.New("unsupported OCR image format (use PNG, JPEG, or WebP)")
		e.failure(err)
		return "", err
	}
	return e.extract(ctx, data, mediaType)
}

// ExtractPDFPage renders one PDF page to a bounded PNG and recognizes it.
func (e *Engine) ExtractPDFPage(ctx context.Context, pdf []byte, page int) (string, error) {
	image, err := e.render(ctx, pdf, page, e.cfg.ScaleTo, e.cfg.MaxImage)
	if err != nil {
		e.failure(err)
		return "", err
	}
	return e.extract(ctx, image, "image/png")
}

func (e *Engine) extract(ctx context.Context, image []byte, mediaType string) (string, error) {
	text, err := e.client.extract(ctx, image, mediaType)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.Calls++
	if err != nil {
		e.stats.Failures++
		e.stats.LastError = err.Error()
		return "", err
	}
	if strings.TrimSpace(text) == "" {
		e.stats.Empty++
	}
	return text, nil
}

func (e *Engine) failure(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.Failures++
	e.stats.LastError = err.Error()
}

// Skip records pages omitted by an explicit OCR coverage limit.
func (e *Engine) Skip(count int, reason string) {
	if count <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.Skipped += count
	e.stats.LastError = reason
}

// Stats returns a concurrency-safe snapshot.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

func (e *Engine) MaxPDFPages() int  { return e.cfg.MaxPDFPages }
func (e *Engine) AllPDFPages() bool { return e.cfg.AllPDFPages }

func imageMediaType(data []byte) (string, bool) {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(http.DetectContentType(data), ";")[0]))
	switch mediaType {
	case "image/png", "image/jpeg", "image/webp":
		return mediaType, true
	default:
		return "", false
	}
}

type requestBody struct {
	Model       string    `json:"model"`
	Messages    []message `json:"messages"`
	Temperature float64   `json:"temperature"`
	MaxTokens   int       `json:"max_tokens"`
	Stream      bool      `json:"stream"`
}

type message struct {
	Role    string        `json:"role"`
	Content []contentPart `json:"content"`
}

type contentPart struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *imageURL `json:"image_url,omitempty"`
}

type imageURL struct {
	URL string `json:"url"`
}

func (c *client) extract(ctx context.Context, image []byte, mediaType string) (string, error) {
	payload := requestBody{
		Model: c.model, Temperature: 0, MaxTokens: c.maxTokens, Stream: false,
		Messages: []message{{
			Role: "user",
			Content: []contentPart{
				{Type: "text", Text: c.prompt},
				{Type: "image_url", ImageURL: &imageURL{
					URL: "data:" + mediaType + ";base64," + base64.StdEncoding.EncodeToString(image),
				}},
			},
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("OCR request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return "", fmt.Errorf("OCR endpoint returned HTTP %d", resp.StatusCode)
	}
	envelopeLimit := c.maxOutput + 1<<20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, envelopeLimit+1))
	if err != nil {
		return "", err
	}
	if int64(len(raw)) > envelopeLimit {
		return "", fmt.Errorf("OCR response exceeds the %d-byte envelope limit", envelopeLimit)
	}
	text, err := responseText(raw)
	if err != nil {
		return "", err
	}
	text = cleanModelOutput(text)
	if int64(len(text)) > c.maxOutput {
		return "", fmt.Errorf("OCR text exceeds the %d-byte output limit", c.maxOutput)
	}
	return text, nil
}

func responseText(raw []byte) (string, error) {
	var response struct {
		Choices []struct {
			Message struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return "", fmt.Errorf("decode OCR response: %w", err)
	}
	if len(response.Choices) == 0 {
		return "", errors.New("OCR response contains no choices")
	}
	content := response.Choices[0].Message.Content
	var text string
	if err := json.Unmarshal(content, &text); err == nil {
		return text, nil
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(content, &parts); err != nil {
		return "", errors.New("OCR response content is neither text nor text parts")
	}
	var out strings.Builder
	for _, part := range parts {
		if part.Text != "" {
			out.WriteString(part.Text)
		}
	}
	return out.String(), nil
}

func cleanModelOutput(text string) string {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "<think>") {
		if _, after, ok := strings.Cut(text, "</think>"); ok {
			text = strings.TrimSpace(after)
		}
	}
	if strings.HasPrefix(text, "```") && strings.HasSuffix(text, "```") {
		if _, after, ok := strings.Cut(text, "\n"); ok {
			text = strings.TrimSpace(strings.TrimSuffix(after, "```"))
		}
	}
	return text
}
