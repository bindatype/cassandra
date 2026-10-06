package orchestrator

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
)

// scriptedModel answers each completion request with the next scripted
// response: an HTTP status and body.
func scriptedModel(t *testing.T, script ...[2]string) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		n := int(atomic.AddInt32(&calls, 1)) - 1
		if n >= len(script) {
			n = len(script) - 1
		}
		status := map[string]int{"200": 200, "400": 400, "429": 429, "502": 502}[script[n][0]]
		w.WriteHeader(status)
		io.WriteString(w, script[n][1])
	}))
	return server, &calls
}

const answered = `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"node02 is fine."}}]}`

func askScripted(t *testing.T, script ...[2]string) (*Session, string, error, int32) {
	t.Helper()
	saved := modelRetryDelay
	modelRetryDelay = time.Millisecond
	t.Cleanup(func() { modelRetryDelay = saved })
	server, calls := scriptedModel(t, script...)
	defer server.Close()
	session := newTestSession(t, server.URL, &fakeConnector{source: broker.SourceWazuhAPI})
	answer, err := session.Ask(context.Background(), "is node02 healthy?")
	return session, answer, err, atomic.LoadInt32(calls)
}

func traced(session *Session, stage string) bool {
	for _, entry := range session.Trace() {
		if entry.Stage == stage {
			return true
		}
	}
	return false
}

func TestATransientModelFailureIsRetriedOnce(t *testing.T) {
	for name, first := range map[string][2]string{
		"HTTP 502":   {"502", "bad gateway"},
		"HTTP 429":   {"429", "slow down"},
		"no choices": {"200", `{"choices":[]}`},
	} {
		t.Run(name, func(t *testing.T) {
			session, answer, err, calls := askScripted(t, first, [2]string{"200", answered})
			if err != nil || answer != "node02 is fine." {
				t.Fatalf("Ask() = %q, %v; want the answer after one retry", answer, err)
			}
			// A direct answer is followed by the documentation lookup, one more
			// call, so the count is at least the try and the retry.
			if calls < 2 || !traced(session, "model_call_retried") || traced(session, "model_call_failed") {
				t.Errorf("calls=%d retried=%v failed=%v, want a recorded retry and no failure",
					calls, traced(session, "model_call_retried"), traced(session, "model_call_failed"))
			}
		})
	}
}

// The failure that started this: the audit record said "failed" and nothing
// else. It must now carry the reason and the turn.
func TestAModelFailureThatPersistsIsRecordedWithItsReason(t *testing.T) {
	session, _, err, calls := askScripted(t, [2]string{"502", "bad gateway"}, [2]string{"502", "bad gateway"})
	if err == nil {
		t.Fatal("two 502s produced no error")
	}
	if calls != 2 {
		t.Errorf("calls = %d, want the first try and one retry", calls)
	}
	if session.event.Status != "failed" || !strings.Contains(session.event.Error, "HTTP 502") ||
		!strings.Contains(session.event.Error, "turn 1") {
		t.Errorf("audit event status=%q error=%q, want failed with the HTTP status and the turn",
			session.event.Status, session.event.Error)
	}
	if !traced(session, "model_call_failed") {
		t.Error("the trace does not record the failure")
	}
}

// A request the gateway rejects would be rejected again: no retry.
func TestAPermanentModelFailureIsNotRetried(t *testing.T) {
	session, _, err, calls := askScripted(t, [2]string{"400", "context length exceeded"}, [2]string{"200", answered})
	if err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d, want an error after one call", err, calls)
	}
	if traced(session, "model_call_retried") || !strings.Contains(session.event.Error, "HTTP 400") {
		t.Errorf("retried=%v error=%q, want no retry and the 400 recorded", traced(session, "model_call_retried"), session.event.Error)
	}
}

func TestAnUnreachableModelIsRecordedAsATransportFailure(t *testing.T) {
	saved := modelRetryDelay
	modelRetryDelay = time.Millisecond
	defer func() { modelRetryDelay = saved }()
	server := httptest.NewServer(http.NotFoundHandler())
	endpoint := server.URL
	server.Close()
	session := newTestSession(t, endpoint, &fakeConnector{source: broker.SourceWazuhAPI})
	if _, err := session.Ask(context.Background(), "is node02 healthy?"); err == nil {
		t.Fatal("an unreachable model produced no error")
	}
	if !traced(session, "model_call_retried") || !strings.Contains(session.event.Error, "transport") {
		t.Errorf("retried=%v error=%q, want a retry and the transport failure recorded",
			traced(session, "model_call_retried"), session.event.Error)
	}
}

func TestAnEmptyAnswerRecordsItsFinishReason(t *testing.T) {
	session, _, err, _ := askScripted(t,
		[2]string{"200", `{"choices":[{"finish_reason":"length","message":{"role":"assistant","content":""}}]}`})
	if err == nil {
		t.Fatal("an empty answer produced no error")
	}
	if !strings.Contains(session.event.Error, `finish_reason "length"`) {
		t.Errorf("audit error = %q, want the finish reason", session.event.Error)
	}
}
