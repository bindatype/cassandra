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
// The translation from a sentence into a query is the part of this system that
// most needs a durable record. It is where a model's judgment enters, it is the
// step no reader of the answer can see, and it is the only thing that explains
// after the fact why a particular number was produced. Until now it existed
// only as -trace output on stderr, which is to say it did not exist.
type AuditEvent struct {
	Timestamp string `json:"timestamp"`
	RequestID string `json:"request_id"`
	Question  string `json:"question"`
	Model     string `json:"model"`

	// Proposed is the model's tool arguments, verbatim and before validation.
	// The denied cases are the interesting ones, and a record that only kept
	// successful requests would omit exactly the events worth reviewing.
	Proposed string          `json:"proposed,omitempty"`
	Decision string          `json:"decision"`
	Plan     json.RawMessage `json:"plan,omitempty"`

	Calls []AuditCall `json:"calls,omitempty"`

	// Trace is every decision the loop made, in order.
	//
	// It was kept in memory and discarded, which left the audit unable to
	// answer questions it looked like it should. A model that sent the same
	// failing request three times records three attempt_failed calls; whether
	// the repeat guidance fired is a trace step, so the only way to find out
	// was to run the question again and hope it failed the same way. That is
	// the argument that put attempt_failed here in the first place, and it
	// applies unchanged to the steps that explain it.
	//
	// The steps that matter most are the ones describing something that did
	// NOT happen -- evidence withheld, a result discarded, a repeat refused --
	// and those leave no other mark anywhere.
	Trace []TraceEntry `json:"trace,omitempty"`

	// Answer is what was actually said, which is the claim the rest of this
	// record exists to check.
	//
	// This field once held only a length, on the reasoning that an answer is
	// reconstructible from the plan and the evidence summary. It is not. The
	// answer is the model's prose over that evidence, and the gap between the
	// two is precisely where this project's wrong answers have lived: a count
	// tallied by hand instead of read from the summary, an empty result
	// reported as an all-clear. Neither is visible in the plan or the summary,
	// because both were correct.
	//
	// It mattered less when answers went to a terminal someone was reading. A
	// scheduled report posts to a channel with nobody watching, and an audit
	// that cannot show what was said cannot check it.
	Answer string `json:"answer,omitempty"`
	// AnswerChars is the true length, kept even when Answer is capped.
	AnswerChars int    `json:"answer_chars,omitempty"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
	DurationMS  int64  `json:"duration_ms"`
}

// AuditCall records one connector execution. The summary is kept and the items
// are not: a fleet inventory is several hundred records, and duplicating those
// into an audit file on every question buys little that the summary does not
// already say.
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
	// Both spend a turn, and a record that kept only the ones that worked
	// could not explain why a question ran out of turns -- which is the case
	// where somebody goes looking at the record.
	Error string `json:"error,omitempty"`
}

// maxAuditAnswer bounds a recorded answer. An answer is a paragraph; anything
// near this is a malfunction, and the cap keeps one from filling the file.
// AnswerChars still records the true length, so a capped record says so.
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
