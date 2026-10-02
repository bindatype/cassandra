package agent

import "encoding/json"

type RequestEnvelope struct {
	RequestID string          `json:"request_id,omitempty"`
	Operation string          `json:"operation"`
	Target    json.RawMessage `json:"target,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
}

type ResponseEnvelope struct {
	RequestID string        `json:"request_id"`
	Operation string        `json:"operation"`
	Status    string        `json:"status"`
	Metadata  ResponseMeta  `json:"metadata"`
	Data      any           `json:"data,omitempty"`
	Error     *ErrorPayload `json:"error,omitempty"`
}

type ResponseMeta struct {
	Timestamp  string `json:"timestamp"`
	DurationMS int64  `json:"duration_ms"`
	Truncated  bool   `json:"truncated"`
	Agent      string `json:"agent"`
	Version    string `json:"version"`
	// Host is the agent's own hostname, on every response, so a caller can
	// check each answer came from the host it addressed (a tunnel can be
	// repointed between calls).
	Host    string         `json:"host"`
	Details map[string]any `json:"details,omitempty"`
}

type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type CapabilitiesResponse struct {
	Operations []OperationCapability `json:"operations"`
	Limits     map[string]any        `json:"limits"`
}

type OperationCapability struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	TargetKinds []string `json:"target_kinds,omitempty"`
}
