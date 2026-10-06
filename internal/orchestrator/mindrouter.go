// Package orchestrator runs the agent loop that connects a human question to
// bounded evidence and back to a synthesized answer.
//
// The model participates twice and holds no authority in either turn. First it
// proposes a structured intent, which trusted broker policy validates and
// resolves into a route plan. Then it receives normalized evidence and writes
// prose. It never selects a connector URL, an API method, a credential, an
// operation, or a filesystem path.
package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// A cold model load on an idle GPU can take over two minutes.
	defaultTimeout   = 300 * time.Second
	maxResponseBytes = 1 << 20
)

// MindRouterConfig carries operator-supplied gateway details.
type MindRouterConfig struct {
	Endpoint         string
	APIKey           string
	Model            string
	Timeout          time.Duration
	MaxResponseBytes int64
	// Thinking asks the chat template for a reasoning phase (Gemma 4 reads
	// enable_thinking). ThinkingBudget caps it; vLLM enforces the cap, but
	// MindRouter dropped the field when measured on 2026-10-01.
	Thinking       bool
	ThinkingBudget int
}

// MindRouterClient speaks the OpenAI-compatible chat completions surface.
type MindRouterClient struct {
	endpoint         string
	apiKey           string
	model            string
	maxResponseBytes int64
	thinking         bool
	thinkingBudget   int
	client           *http.Client
}

// NewMindRouterClient validates configuration and returns a client.
func NewMindRouterClient(config MindRouterConfig) (*MindRouterClient, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("mindrouter endpoint is required")
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse mindrouter endpoint: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("mindrouter endpoint must be http or https")
	}
	if config.APIKey == "" {
		return nil, fmt.Errorf("mindrouter api key is required")
	}
	if config.Model == "" {
		return nil, fmt.Errorf("mindrouter model is required")
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	maxBytes := config.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = maxResponseBytes
	}

	return &MindRouterClient{
		endpoint:         strings.TrimRight(config.Endpoint, "/"),
		apiKey:           config.APIKey,
		model:            config.Model,
		maxResponseBytes: maxBytes,
		thinking:         config.Thinking,
		thinkingBudget:   config.ThinkingBudget,
		client:           &http.Client{Timeout: timeout},
	}, nil
}

// Message is one chat message. ToolCalls is set on assistant turns that request
// a tool; ToolCallID and Name are set on tool result turns.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

// ToolCall is a model-proposed tool invocation.
type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// Choice is one completion alternative.
type Choice struct {
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

type completionResponse struct {
	Choices []Choice `json:"choices"`
	Error   *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// Complete sends one chat completion request and returns the first choice.
// forceTool names a function the model must call; empty leaves the choice to
// the model, so it can decline a question no source can answer.
//
// gemma4-31b-vllm honours a forced call (measured 2026-10-02); the ollama
// models behind MindRouter did not (2026-08-27). Callers must still handle a
// response that describes a call instead of making one.
// ModelCallError is a failed call to the model, marked transient when the same
// request could succeed on another try: a transport failure, HTTP 429 or 5xx,
// or a response with no choices. Other failures (a 4xx such as a rejected key
// or an oversized request, an oversized or undecodable response) would fail
// the same way again.
type ModelCallError struct {
	Transient bool
	Err       error
}

func (e *ModelCallError) Error() string { return e.Err.Error() }
func (e *ModelCallError) Unwrap() error { return e.Err }

func modelCallError(transient bool, err error) error {
	return &ModelCallError{Transient: transient, Err: err}
}

func (c *MindRouterClient) Complete(ctx context.Context, messages []Message, tools []any, forceTool string) (Choice, error) {
	body := map[string]any{
		"model":    c.model,
		"messages": messages,
	}
	if c.thinking {
		body["chat_template_kwargs"] = map[string]any{"enable_thinking": true}
		if c.thinkingBudget > 0 {
			body["thinking_token_budget"] = c.thinkingBudget
		}
	}
	if len(tools) > 0 {
		body["tools"] = tools
		if forceTool != "" {
			body["tool_choice"] = map[string]any{
				"type":     "function",
				"function": map[string]any{"name": forceTool},
			}
		} else {
			body["tool_choice"] = "auto"
		}
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return Choice{}, fmt.Errorf("encode completion request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return Choice{}, fmt.Errorf("build completion request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.apiKey)

	response, err := c.client.Do(request)
	if err != nil {
		// A cancelled or expired question is not worth another try.
		return Choice{}, modelCallError(ctx.Err() == nil, fmt.Errorf("mindrouter transport: %w", err))
	}
	defer response.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return Choice{}, modelCallError(ctx.Err() == nil, fmt.Errorf("read completion response: %w", err))
	}
	if int64(len(raw)) > c.maxResponseBytes {
		return Choice{}, modelCallError(false, fmt.Errorf("mindrouter response exceeded %d bytes", c.maxResponseBytes))
	}
	if response.StatusCode != http.StatusOK {
		transient := response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500
		return Choice{}, modelCallError(transient,
			fmt.Errorf("mindrouter returned HTTP %s: %s", strconv.Itoa(response.StatusCode), truncate(string(raw), 300)))
	}

	var decoded completionResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return Choice{}, modelCallError(false, fmt.Errorf("decode completion response: %w", err))
	}
	if decoded.Error != nil {
		return Choice{}, modelCallError(false, fmt.Errorf("mindrouter error: %s", decoded.Error.Message))
	}
	if len(decoded.Choices) == 0 {
		return Choice{}, modelCallError(true, fmt.Errorf("mindrouter returned no choices"))
	}
	return decoded.Choices[0], nil
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
