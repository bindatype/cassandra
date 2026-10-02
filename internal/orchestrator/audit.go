package orchestrator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent records one question, from what the model proposed through what
// executed to what came back.
//
// The translation from a sentence into a query is where the model's judgment
// enters and the step no reader of the answer can see, so it gets a durable
// record.
type AuditEvent struct {
	Timestamp string `json:"timestamp"`
	RequestID string `json:"request_id"`
	Question  string `json:"question"`
	Model     string `json:"model"`
	// Caller is the person a shared service answered for, and Client the agent
	// they connected with as it names itself (claude-code, hermes, ...).
	// Self-reported, so not proof, but it is how a cloud agent receiving GW
	// data shows up in the record. Both are empty for a local askcass run.
	Caller string `json:"caller,omitempty"`
	Client string `json:"client,omitempty"`

	// Proposed is the model's first tool arguments, verbatim and before
	// validation, so denied requests are on record too.
	Proposed string          `json:"proposed,omitempty"`
	Decision string          `json:"decision"`
	Plan     json.RawMessage `json:"plan,omitempty"`

	Calls []AuditCall `json:"calls,omitempty"`

	// Trace is every decision the loop made, in order. The steps that matter
	// most describe something that did NOT happen (evidence withheld, a
	// result discarded, a repeat refused), and they leave no other mark.
	Trace []TraceEntry `json:"trace,omitempty"`

	// Answer is what was actually said. It can't be reconstructed from the
	// plan and evidence: the wrong answers live in the gap between correct
	// evidence and the prose written over it.
	Answer string `json:"answer,omitempty"`
	// AnswerChars is the true length, kept even when Answer is capped.
	AnswerChars int    `json:"answer_chars,omitempty"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
	DurationMS  int64  `json:"duration_ms"`
}

// AuditCall records one connector execution: the summary, not the items,
// which can be hundreds of records per question.
type AuditCall struct {
	Source     string         `json:"source"`
	Action     string         `json:"action"`
	Endpoint   string         `json:"endpoint"`
	Query      string         `json:"query,omitempty"`
	DurationMS int64          `json:"duration_ms"`
	ItemCount  int            `json:"item_count"`
	Truncated  bool           `json:"truncated"`
	Summary    map[string]int `json:"summary,omitempty"`

	// Error marks an attempt that failed rather than a call that returned.
	// Both spend a turn, so both are recorded.
	Error string `json:"error,omitempty"`
}

// maxAuditAnswer bounds a recorded answer so a malfunction can't fill the
// file. AnswerChars still records the true length.
const maxAuditAnswer = 8192

// Auditor appends events to a JSON-lines file.
type Auditor struct {
	mu   sync.Mutex
	file *os.File
}

// NewAuditor opens the audit file, creating it with owner-only permissions and
// correcting the mode if it already exists with weaker ones.
func NewAuditor(path string) (*Auditor, error) {
	if directory := filepath.Dir(path); directory != "" {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &Auditor{file: file}, nil
}

// Close releases the audit file.
func (a *Auditor) Close() error { return a.file.Close() }

// Record appends one event. A short write is treated as a failure, matching the
// endpoint agent: a partially written line is not a record.
func (a *Auditor) Record(event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if len(event.Answer) > maxAuditAnswer {
		event.Answer = event.Answer[:maxAuditAnswer] + "\u2026 [truncated]"
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')

	written, err := a.file.Write(encoded)
	if err != nil {
		return err
	}
	if written != len(encoded) {
		return fmt.Errorf("short audit write: %d of %d bytes", written, len(encoded))
	}
	return nil
}
