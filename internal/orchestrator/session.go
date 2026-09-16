package orchestrator

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bindatype/cassandra/internal/broker"
	"github.com/bindatype/cassandra/internal/connector"
	"github.com/bindatype/cassandra/internal/env"
)

//go:embed prompt.md
var embeddedPrompt string

// systemPrompt is the embedded prompt with its rule markers stripped, unless
// CASS_PROMPT names a file to use instead. The override exists so a prompt
// change can be measured without a rebuild; nothing in normal operation reads
// it.
var systemPrompt = loadPrompt()

// ruleMarker labels a block so an experiment can remove it by name. Markers are
// stripped before the prompt is sent, so the model never sees them.
var ruleMarker = regexp.MustCompile(`(?m)^<!-- rule:([a-z0-9-]+) -->\n`)

var ruleEnd = regexp.MustCompile(`(?m)^<!-- /rule -->\n`)

func loadPrompt() string {
	text := embeddedPrompt
	if path := env.Get("CASS_PROMPT"); path != "" {
		if raw, err := os.ReadFile(path); err == nil {
			text = string(raw)
		}
	}
	text = ruleMarker.ReplaceAllString(text, "")
	return strings.TrimSpace(ruleEnd.ReplaceAllString(text, "")) + "\n"
}

// PromptRules lists the rule blocks the current prompt defines, in order.
func PromptRules() []string {
	var names []string
	for _, match := range ruleMarker.FindAllStringSubmatch(embeddedPrompt, -1) {
		names = append(names, match[1])
	}
	return names
}

const (
	toolName = "cass_evidence"
	// Headroom above what any connector will return, so evidence is rejected
	// here only if a connector's own bound has failed. CASS_MAX_EVIDENCE
	// raises it in step with a raised connector cap.
	maxEvidenceJSON = 64 * 1024

	// maxToolCalls bounds the work, not the authority: each call is validated
	// and authorized exactly as the first one is. Five is enough to look at a
	// schema, run a query, and correct it once.
	maxToolCalls = 5

	// servedContextTokens is what the gateway actually serves, measured rather
	// than read from configuration -- the two disagreed for a month.
	//
	// Measured against gemma4-31b-vllm by scripts/ctx_marker_probe.py, which
	// plants a marker at the head, the middle, and the tail of an oversized
	// prompt and asks which survived. All three were reported at every size up
	// to 127,500 served tokens; 140,000 was refused outright with HTTP 400,
	// "This model's maximum context length is 131072 tokens".
	//
	// That refusal is the important half. The previous backend, gemma4:31b on
	// ollama behind MindRouter, served 32,768 and did not refuse: it discarded
	// the HEAD and kept the tail, so an oversized request reported only the
	// last marker. The head is the system prompt, so every safety rule was the
	// first thing thrown away, silently, exactly when the context was largest.
	// vLLM fails loudly instead. The guard stays because a refusal with a
	// stated reason still beats a 400 in the user's face, and because nothing
	// stops an ollama-backed model being registered here again.
	//
	// Re-measure after any gateway or model change. That instruction is not
	// decoration: this constant was 32,768 and correct until the backend moved.
	servedContextTokens = 131072

	// Two ratios, because one is wrong for half the content. Both are measured
	// against the served tokenizer and both are rounded DOWN past the densest
	// sample seen, so the estimate runs high: refusing early is recoverable,
	// overshooting the window is not.
	//
	// Rounding down is the whole discipline, and it was got wrong once. These
	// were 2.5 and 4.3, taken from a single sample each; re-measuring across
	// three live intents found evidence denser than 2.5 and prose denser than
	// 4.3, which made the guard optimistic in the one direction it must never
	// be. Take the worst case, not the average.
	//
	// jsonCharsPerToken: live evidence measured 2.27 (fleet.inventory, 23,232
	// chars), 2.59 (tickets.open, 36,664) and 2.73 (monitoring.problems,
	// 9,273). The densest governs. Structured JSON is thick with punctuation,
	// and the more uniform the records the worse it gets.
	//
	// proseCharsPerToken: the 29,420-byte prompt measured 7,261 tokens, which
	// is 4.05. Using the JSON figure for prose would overstate it by 84% and
	// leave no room for evidence that in fact fits.
	jsonCharsPerToken  = 2.2
	proseCharsPerToken = 4.0

	// answerReserveTokens is room kept for the reply. Nothing sets max_tokens
	// on the request, so the answer competes with the input for one window.
	answerReserveTokens = 1500
)

// ToolDefinition is the single tool exposed to the model. Its schema is the
// entire surface a model can influence: an intent, and optionally a host or
// resource alias. Everything else about execution is resolved by policy.
func ToolDefinition(intents []string) any {
	return map[string]any{
		"type": "function",
		"function": map[string]any{
			"name": toolName,
			"description": "Retrieve bounded, read-only infrastructure evidence through the Cass policy broker. " +
				"Covers Wazuh agent inventory and connection state; Zabbix triggers firing now and the Zabbix " +
				"event log for a past window; a policy-approved file read from an authorized Cass endpoint; " +
				"one read-only SQL SELECT against the pegasusdb HPC accounting database; and open Request " +
				"Tracker tickets in allowlisted queues, metadata only. " +
				"Does NOT cover vulnerabilities or CVEs, installed packages, patch level, log contents, user " +
				"accounts, configuration, performance metrics or history, ticket content or correspondence, " +
				"or any file outside the policy's resource list. " +
				"Do not call this for questions it cannot answer.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"intent": map[string]any{
						"type":        "string",
						"enum":        intents,
						"description": "Which bounded question to ask.",
					},
					"host": map[string]any{
						"type":        "string",
						"description": "Host selector. Required for agent.status, live.evidence, and tickets.for_host.",
					},
					"resource": map[string]any{
						"type":        "string",
						"description": "Policy-defined resource alias. For live.evidence ONLY. Never put SQL here.",
					},
					"query": map[string]any{
						"type":        "string",
						"description": "The SQL for database.query, and the only field SQL may go in. One read-only SELECT, bounded by WHERE.",
					},
					"until": map[string]any{
						"type": "string",
						"description": "Close the window since opens. Same forms; a plain date means the end of that day. " +
							"For monitoring.problems, monitoring.history, tickets.open, and tickets.for_host only. " +
							"Without it a bound is a ray, and a question about one past day is answered from today. " +
							"For tickets.open/tickets.for_host this bounds Created (ticket age), not last activity, " +
							"and stands alone: \"older than 60 days\" is until: 60d with no since, because adding " +
							"one would cut off the oldest tickets the question is about.",
					},
					"since": map[string]any{
						"type": "string",
						"description": "For monitoring.problems/monitoring.history, bound evidence to what CHANGED after this " +
							"moment. For tickets.open/tickets.for_host, bound evidence to tickets CREATED after this " +
							"moment -- ticket age, never a reason a still-open ticket goes missing. RFC 3339, a date " +
							"such as 2026-08-28, or a window such as 24h or 7d. " +
							"Not for database.query, which bounds time in its WHERE clause; not for fleet.inventory, " +
							"agent.status, or live.evidence, which report current state and refuse a bound rather than " +
							"ignore it. A question about what is wrong NOW takes no bound, whatever time it mentions.",
					},
					"match": map[string]any{
						"type": "string",
						"description": "Narrow monitoring evidence to problems whose name contains this text, " +
							"case-insensitively, as a plain substring rather than a pattern. " +
							"For monitoring.problems and monitoring.history only. " +
							"Reach for it whenever the question names a kind of problem: " +
							"match \"Zabbix agent is not available\" rather than reading a general page and looking for it.",
					},
					"severity": map[string]any{
						"type": "string",
						"enum": broker.SeverityNames(),
						"description": "Return only problems at this level or worse. " +
							"For monitoring.problems and monitoring.history only.",
					},
					"state": map[string]any{
						"type": "string",
						"enum": []string{broker.StateProblem, broker.StateResolved},
						"description": "For monitoring.history only. The event log records both an incident opening " +
							"and its closing, so one incident inside the window appears twice. " +
							"Choose \"problem\" for what broke and \"resolved\" for what recovered; omit for both.",
					},
					"limit": map[string]any{
						"type":    "integer",
						"minimum": 1,
						"maximum": broker.MaxMonitoringLimit,
						"description": fmt.Sprintf(
							"How many rows to return, default %d, maximum %d. "+
								"For monitoring.problems and monitoring.history only. "+
								"Raising it does not make a large result answerable: read total_matching and "+
								"breakdown, and narrow with match, severity, or a tighter window instead.",
							broker.DefaultMonitoringLimit, broker.MaxMonitoringLimit),
					},
				},
				"required":             []string{"intent"},
				"additionalProperties": false,
			},
		},
	}
}

// Session runs one question through the model, the broker, and back.
type Session struct {
	client   *MindRouterClient
	router   *broker.Router
	executor *connector.Executor
	intents  []string
	auditor  *Auditor
	model    string
	trace    []TraceEntry
	event    AuditEvent
	started  time.Time
}

// WithAudit attaches an audit destination. Without one the session still works
// but leaves no record, which is the state this replaced.
func (s *Session) WithAudit(auditor *Auditor, model string) *Session {
	s.auditor = auditor
	s.model = model
	return s
}

// TraceEntry records one step of the loop so an operator can see exactly what
// the model proposed and what policy did with it.
type TraceEntry struct {
	Stage   string `json:"stage"`
	Detail  string `json:"detail"`
	Allowed bool   `json:"allowed"`
}

// NewSession wires a model client to a policy router and an executor.
//
// Only intents whose source the executor can actually reach are offered to the
// model. Advertising an intent with no connector behind it presents a
// capability that does not exist, which is the same failure as answering a
// question from a source that cannot see it.
func NewSession(client *MindRouterClient, router *broker.Router, executor *connector.Executor) *Session {
	available := make(map[broker.Source]bool)
	for _, source := range executor.Sources() {
		available[source] = true
	}
	var intents []string
	for _, intent := range broker.AllIntents() {
		if source, ok := broker.SourceForIntent(intent); ok && available[source] {
			intents = append(intents, string(intent))
		}
	}
	return &Session{client: client, router: router, executor: executor, intents: intents}
}

// Intents lists what this session can actually offer a model.
func (s *Session) Intents() []string { return s.intents }

// Trace returns the decisions made during the last Ask.
func (s *Session) Trace() []TraceEntry {
	return s.trace
}

// Ask answers a question, letting the model work in steps.
//
// It gets several tool calls rather than one. A single call forces every
// question into a single query, which is the wrong shape for the work: asked
// about an unfamiliar table the model reaches for information_schema, and with
// one call that inspection consumes the only turn it had. It would report the
// columns and stop, having never answered. Given room, it can look before it
// queries, count before it aggregates, and correct a query the database
// rejected -- which is how a person would do it.
//
// Every call is validated and authorized independently. More turns is more
// opportunity to work, not more authority.
// estimatedTokens is a deliberately pessimistic size for what will be sent.
//
// There is no tokenizer here, so this counts characters and divides by the
// densest ratio measured. It exists to keep the request under a limit whose
// breach is silent, and a guard against a silent failure has to err toward
// refusing early.
func estimatedTokens(messages []Message, tools []any) int {
	tokens := 0
	for _, m := range messages {
		// A tool message carries evidence JSON; everything else is prose the
		// model or the operator wrote.
		ratio := proseCharsPerToken
		if m.Role == "tool" {
			ratio = jsonCharsPerToken
		}
		chars := len(m.Role) + len(m.Content) + len(m.Name) + len(m.ToolCallID)
		for _, c := range m.ToolCalls {
			chars += len(c.ID) + len(c.Function.Name) + len(c.Function.Arguments)
		}
		tokens += int(float64(chars) / ratio)
	}
	if encoded, err := json.Marshal(tools); err == nil {
		tokens += int(float64(len(encoded)) / jsonCharsPerToken)
	}
	return tokens + answerReserveTokens
}

// roomForMore reports whether another payload of this size can be added
// without the gateway silently discarding the head of the request.
func roomForMore(messages []Message, tools []any, addition int) (int, bool) {
	projected := estimatedTokens(messages, tools) + int(float64(addition)/jsonCharsPerToken)
	return projected, projected <= servedContextTokens
}

// discloseWithheldEvidence appends the limitation when the model did not.
//
// Every mechanism in this project that expressed an absence by omission has
// been read the reassuring way. A partial answer that does not say it is
// partial is the same failure with a new cause.
func discloseWithheldEvidence(answer string, withheld bool) string {
	if !withheld {
		return answer
	}
	low := strings.ToLower(answer)
	for _, said := range []string{"withheld", "incomplete", "not all", "partial"} {
		if strings.Contains(low, said) {
			return answer
		}
	}
	return answer + "\n\nThis answer is incomplete: further evidence was withheld because " +
		"returning it would have exceeded the model's context. Ask a narrower question to see the rest."
}

func (s *Session) Ask(ctx context.Context, question string) (string, error) {
	s.trace = nil
	s.started = time.Now()
	s.event = AuditEvent{
		RequestID: newRequestID(),
		Question:  question,
		Model:     s.model,
		Decision:  "no_tool_call",
		Status:    "answered",
	}
	defer s.writeAudit()

	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: question},
	}
	tools := []any{ToolDefinition(s.intents)}

	forceTool := ""
	budgetReached := false

	// What each turn actually did. Without this the only thing the loop could
	// say on the way out was its own constant: "gave up after 5 tool calls",
	// whether it had spent five turns on five different theories or three of
	// them re-submitting one query that had already failed twice. Those need
	// different responses from whoever reads the message, so the message has
	// to tell them apart.
	succeeded, failed := 0, 0
	seenFailure := map[string]string{}
	seenError := map[string]bool{}
	var lastError string
	for turn := 0; turn < maxToolCalls; turn++ {
		choice, err := s.client.Complete(ctx, messages, tools, forceTool)
		forceTool = ""
		if err != nil {
			return "", err
		}

		if len(choice.Message.ToolCalls) == 0 {
			answer := strings.TrimSpace(choice.Message.Content)

			// A weaker model sometimes writes out the call it means to make --
			// the SQL, the arguments, sometimes a code block -- and stops,
			// having described the action instead of taking it. Returning that
			// hands the caller a plan where an answer should be. With turns
			// left, ask again.
			if describesACallInstead(answer) && turn < maxToolCalls-1 {
				// Asking again in prose is what failed the first time. The next
				// turn names the function in tool_choice, so a call is the only
				// shape the response can take.
				s.record("described_instead_of_called", "model wrote out a tool call rather than making one; forcing the call", false)
				messages = append(messages,
					Message{Role: "assistant", Content: answer},
					Message{Role: "user", Content: "Make that call now."},
				)
				forceTool = toolName
				continue
			}

			if answer == "" {
				s.record("empty_answer", "model returned neither a tool call nor content", false)
				s.event.Status = "failed"
				return "", fmt.Errorf("model returned neither a tool call nor an answer")
			}
			if turn == 0 {
				s.record("model_answered_directly", "no tool call proposed", true)
			} else {
				s.record("answer_synthesized", "", true)
			}
			// A result was withheld to keep the request inside the context.
			// The model was told to say so; if it did not, the answer says it
			// anyway. This is a fact about what was gathered, not a claim
			// about the subject, and an answer that omits it reads as complete.
			answer = discloseWithheldEvidence(answer, budgetReached)

			s.event.Answer = answer
			s.event.AnswerChars = len(answer)
			return answer, nil
		}

		call := choice.Message.ToolCalls[0]
		if call.Function.Name != toolName {
			s.record("tool_rejected", fmt.Sprintf("model requested unknown tool %q", call.Function.Name), false)
			return "", fmt.Errorf("model requested unknown tool %q", call.Function.Name)
		}
		s.record("intent_proposed", call.Function.Arguments, true)
		if s.event.Proposed == "" {
			s.event.Proposed = call.Function.Arguments
		}

		// The model's arguments are untrusted input on every turn, not just the
		// first. They are decoded as strictly as any route request and
		// authorized by policy before anything executes.
		messages = append(messages, Message{
			Role: "assistant", Content: choice.Message.Content, ToolCalls: choice.Message.ToolCalls,
		})

		result, failure := s.runOneCall(ctx, call)
		if failure != nil {
			// A refusal is an answer and ends the loop. A malformed call or a
			// failed query is something the model can correct, so it goes back
			// as a tool result and the loop continues.
			if !failure.recoverable {
				s.event.Decision = "denied"
				return "", failure.err
			}
			failed++
			lastError = failure.err.Error()

			// A failed attempt spends a turn, so it is the reason a question
			// runs out of them. Recording only successes made the audit for a
			// five-turn failure show two calls and no explanation, and the
			// only way to find out what the other three were was to run the
			// question again with -trace and hope it failed the same way.
			attemptedQuery := queryFromArguments(call.Function.Arguments)
			s.event.Calls = append(s.event.Calls, AuditCall{
				Source: "orchestrator",
				Action: "attempt_failed",
				Query:  attemptedQuery,
				Error:  lastError,
			})

			// Feeding back the same "correct this and call again" to a model
			// that has already made this exact mistake invites the same fix.
			// It happened: one question spent turns 1, 2 and 5 on
			// PERCENTILE_CONT(x) OVER () -- rejected each time by MariaDB for
			// want of WITHIN GROUP (ORDER BY ...) -- and turn 5 was turn 1
			// again. Naming the repeat is cheap and is the difference between
			// a turn spent re-deriving and a turn spent elsewhere.
			//
			// Two signals, because the query text alone missed the case that
			// prompted this. Turns 1 and 4 of one failed question were the
			// same construction differing only by a DISTINCT, so comparing
			// query text saw two different queries while the database saw one
			// mistake twice. The error is the better discriminator: an
			// identical error means the construction is wrong, not the
			// spelling, and re-sending a variant of it cannot help.
			guidance := "Correct this and call the tool again."
			if previous, repeat := seenFailure[normalizeQuery(attemptedQuery)]; repeat {
				guidance = "You have already sent this exact query in this " +
					"conversation and it failed the same way: " + previous +
					". Do not send it again. Use a different construction."
				s.record("repeated_failing_query",
					"model re-sent a query that already failed", false)
			} else if seenError[lastError] {
				guidance = "This same error has already occurred in this " +
					"conversation. The construction is wrong, not the " +
					"formatting, so re-spelling it will fail again. Read the " +
					"error text for what the statement is missing, and if it " +
					"names no fix, ask the schema or use a different approach."
				s.record("repeated_failing_error",
					"a different query produced an error already seen", false)
			}
			seenFailure[normalizeQuery(attemptedQuery)] = lastError
			seenError[lastError] = true

			messages = append(messages, Message{
				Role: "tool", ToolCallID: call.ID, Name: toolName,
				Content: fmt.Sprintf(`{"error":%q,"guidance":%q}`, lastError, guidance),
			})
			continue
		}

		evidenceJSON, err := json.Marshal(result)
		if err != nil {
			return "", fmt.Errorf("encode evidence: %w", err)
		}
		if len(evidenceJSON) > evidenceBudget() {
			messages = append(messages, Message{
				Role: "tool", ToolCallID: call.ID, Name: toolName,
				Content: `{"error":"the result was too large to return; narrow it or aggregate in SQL"}`,
			})
			continue
		}

		// The per-result cap says nothing about the total. Every result stays
		// in the history, so five of them are sent together on the last turn,
		// and the gateway responds to an oversized request by discarding the
		// head rather than refusing it. Refusing here is the difference between
		// an answer that says what it is missing and one that quietly lost its
		// own instructions.
		if projected, ok := roomForMore(messages, tools, len(evidenceJSON)); !ok {
			s.record("evidence_withheld_for_context",
				fmt.Sprintf("adding %d bytes would reach about %d tokens against a served limit of %d",
					len(evidenceJSON), projected, servedContextTokens), false)
			budgetReached = true
			messages = append(messages, Message{
				Role: "tool", ToolCallID: call.ID, Name: toolName,
				Content: `{"error":"this result was withheld: returning it would exceed the model context ` +
					`and silently discard your instructions","guidance":"Answer from the evidence you ` +
					`already have, and state plainly that further evidence was withheld and the answer ` +
					`is therefore incomplete."}`,
			})
			continue
		}

		succeeded++
		s.record("evidence_collected", fmt.Sprintf("%d source(s)", len(result.Evidence)), true)
		for _, evidence := range result.Evidence {
			s.event.Calls = append(s.event.Calls, AuditCall{
				Source:     evidence.Source,
				Action:     evidence.Action,
				Endpoint:   evidence.Endpoint,
				Query:      evidence.Query,
				DurationMS: evidence.DurationMS,
				ItemCount:  evidence.ItemCount,
				Truncated:  evidence.Truncated,
				Summary:    evidence.Summary,
			})
		}
		messages = append(messages, Message{
			Role: "tool", ToolCallID: call.ID, Name: toolName, Content: string(evidenceJSON),
		})
	}

	// "gave up after 5 tool calls" named the limit rather than the run, which
	// reads as "the limit is too low" no matter what actually went wrong. Say
	// how the turns were spent instead, so the next question is the right one:
	// raise the limit, fix the query, or look at the source.
	detail := fmt.Sprintf("%d succeeded, %d failed", succeeded, failed)
	if repeats := failed - len(seenError); repeats > 0 {
		detail += fmt.Sprintf(", %d of them repeating an error already seen", repeats)
	}
	if lastError != "" {
		detail += "; last error: " + lastError
	}
	s.record("turn_limit_reached", detail, false)
	s.event.Status = "failed"
	s.event.Error = detail
	return "", fmt.Errorf("gave up after %d attempts (%s)", maxToolCalls, detail)
}

// callFailure distinguishes a refusal, which ends the loop, from a mistake the
// model can fix, which is returned to it.
type callFailure struct {
	err         error
	recoverable bool
}

// runOneCall validates, authorizes and executes one proposed tool call.
func (s *Session) runOneCall(ctx context.Context, call ToolCall) (connector.Result, *callFailure) {
	request, err := broker.DecodeRouteRequest(newLimitedReader(call.Function.Arguments))
	if err != nil {
		s.record("intent_rejected", err.Error(), false)
		return connector.Result{}, &callFailure{err: fmt.Errorf("undecodable intent: %w", err), recoverable: true}
	}

	plan, err := s.router.Plan(request)
	if err != nil {
		s.record("policy_denied", err.Error(), false)
		// Record the denial even when the model will be allowed another
		// attempt. A request denied and then retried is not the same as one
		// that never proposed anything, and "no_tool_call" says the wrong
		// thing about a model that proposed an intent that does not exist.
		if s.event.Decision == "no_tool_call" {
			s.event.Decision = "denied"
		}
		// Being told a host is not authorized is an answer. Putting a value in
		// the wrong field is a mistake. Only the second earns another attempt.
		return connector.Result{}, &callFailure{
			err:         fmt.Errorf("policy denied the proposed intent: %w", err),
			recoverable: isRetryableRouteError(err),
		}
	}
	planJSON, _ := json.Marshal(plan)
	s.record("policy_allowed", string(planJSON), true)
	s.event.Decision = "allowed"
	s.event.Plan = planJSON

	result, err := s.executor.Execute(ctx, plan)
	if err != nil {
		s.record("execution_failed", err.Error(), false)
		return connector.Result{}, &callFailure{err: err, recoverable: true}
	}
	return result, nil
}

// writeAudit records the event, filling in the outcome from the trace. It runs
// on every path out of Ask, so a denial or a failure is recorded as faithfully
// as an answer.
func (s *Session) writeAudit() {
	if s.auditor == nil {
		return
	}
	s.event.DurationMS = time.Since(s.started).Milliseconds()
	if s.event.AnswerChars == 0 && s.event.Status == "answered" {
		s.event.Status = "failed"
		for _, entry := range s.trace {
			if !entry.Allowed {
				s.event.Error = entry.Stage + ": " + entry.Detail
			}
		}
	}
	if err := s.auditor.Record(s.event); err != nil {
		// Deliberately visible. An audit that fails quietly is worse than none,
		// because it invites the belief that a record exists.
		fmt.Fprintf(os.Stderr, "cass: AUDIT WRITE FAILED: %v\n", err)
	}
}

// newRequestID returns a short correlation identifier.
func newRequestID() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}

// record appends a decision to the trace, which -trace prints and which
// writeAudit reads to describe the outcome.
func (s *Session) record(stage, detail string, allowed bool) {
	s.trace = append(s.trace, TraceEntry{Stage: stage, Detail: detail, Allowed: allowed})
}

// isRetryableRouteError reports whether a denial describes a malformed request
// rather than a refused one. Authorization outcomes are never retried: putting
// a value in the wrong field is a mistake the model can fix, while being told a
// host is not authorized is an answer, and offering another attempt would turn
// a refusal into an invitation to look for a host that is.
func isRetryableRouteError(err error) bool {
	var routeErr *broker.RouteError
	if !errors.As(err, &routeErr) {
		return false
	}
	switch routeErr.Code {
	case "invalid_request", "invalid_query", "invalid_since", "invalid_host", "invalid_resource",
		"missing_host", "missing_resource", "unknown_intent":
		return true
	default:
		return false
	}
}

// describesACallInstead reports whether an answer looks like a tool call that
// was written out rather than issued. It is a heuristic over model prose, so
// it errs toward letting text through: the cost of a false positive is one
// wasted turn, while a false negative returns a plan to someone who asked a
// question.
func describesACallInstead(answer string) bool {
	if answer == "" {
		return false
	}
	lowered := strings.ToLower(answer)

	// Naming the tool, or naming an intent, while producing no call at all.
	mentionsTheCall := strings.Contains(lowered, strings.ToLower(toolName)) ||
		strings.Contains(lowered, "intent=") ||
		strings.Contains(lowered, `"intent":`) ||
		strings.Contains(lowered, "intent='")

	// Announcing the action rather than reporting a result.
	announces := strings.Contains(lowered, "let's execute") ||
		strings.Contains(lowered, "lets execute") ||
		strings.Contains(lowered, "i will now") ||
		strings.Contains(lowered, "now i will") ||
		strings.Contains(lowered, "let's construct") ||
		strings.Contains(lowered, "i need to query") ||
		strings.Contains(lowered, "execute this via the tool")

	return mentionsTheCall || announces
}

// evidenceBudget is the largest evidence payload this session will hand a
// model. It tracks the connector caps: raising one without the other produces
// a query that succeeds and is then refused.
func evidenceBudget() int {
	if value := env.Get("CASS_MAX_EVIDENCE"); value != "" {
		if size, err := strconv.Atoi(value); err == nil && size > 0 {
			return size
		}
	}
	return maxEvidenceJSON
}

// queryFromArguments pulls the SQL out of a tool call for the record. The
// arguments are the model's, so they may not parse; an unparsable call is
// still worth recording verbatim, because "the model sent something that was
// not JSON" is itself the finding.
func queryFromArguments(arguments string) string {
	var parsed struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal([]byte(arguments), &parsed); err != nil || parsed.Query == "" {
		return arguments
	}
	return parsed.Query
}

// normalizeQuery collapses whitespace and case so that the same query sent
// twice is recognised as the same query. It is deliberately loose: the point
// is to catch a model re-deriving an identical mistake through slightly
// different formatting, not to decide SQL equivalence, which is not something
// string comparison can do.
func normalizeQuery(query string) string {
	return strings.ToLower(strings.Join(strings.Fields(query), " "))
}
