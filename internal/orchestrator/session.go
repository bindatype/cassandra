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
	// The per-result evidence cap. Connector caps sit below it, so it fires
	// only when a connector's own bound has failed, and an oversized result
	// is discarded whole. CASS_MAX_EVIDENCE raises it in step with a raised
	// connector cap.
	maxEvidenceJSON = 64 * 1024

	// maxToolCalls bounds the work, not the authority: each call is validated
	// and authorized exactly as the first one is. Five is enough to look at a
	// schema, run a query, and correct it once.
	maxToolCalls = 5

	// servedContextTokens is the context gemma4-31b-vllm was measured to serve
	// by scripts/ctx_marker_probe.py on 2026-09-04, not read from config. The
	// gateway has reported 244,000 since vLLM's max-model-len was raised;
	// that is not yet re-measured, and a low value errs safe. vLLM refuses an
	// oversized request with HTTP 400; an ollama backend instead silently
	// drops the head of the request, which is the system prompt. roomForMore
	// covers both. Re-measure after any gateway or model change.
	servedContextTokens = 131072

	// Characters per token, measured against the served tokenizer: JSON
	// evidence and prose differ by nearly 2x. Both are rounded down past the
	// densest sample measured, so the estimate runs high; refusing early is
	// recoverable, overshooting is not. Take the worst case, never the
	// average.
	jsonCharsPerToken  = 2.2
	proseCharsPerToken = 4.0

	// answerReserveTokens is room kept for the reply. Nothing sets max_tokens
	// on the request, so the answer competes with the input for one window.
	answerReserveTokens = 1500
)

// ToolDefinition is the single tool exposed to the model. Its schema is the
// entire surface a model can influence: an intent plus its optional
// selectors. Everything else about execution is resolved by policy.
func ToolDefinition(intents []string) any {
	return toolDefinition(intents, nil, nil)
}

// toolDefinition builds the schema, naming the live targets the policy
// authorizes when there are any.
//
// The enum goes on resource, not host: a resource alias means something only
// to live.evidence, but a host is also a Wazuh agent name and an RT subject,
// and an enum there would refuse hosts with no endpoint agent.
func toolDefinition(intents, liveHosts, liveResources []string) any {
	definition := map[string]any{
		"type": "function",
		"function": map[string]any{
			"name": toolName,
			"description": "Retrieve bounded, read-only infrastructure evidence through the Cass policy broker. " +
				"Covers Wazuh agent inventory and connection state; Zabbix triggers firing now and the Zabbix " +
				"event log for a past window; a policy-approved file read from an authorized Cass endpoint; " +
				"one read-only SQL SELECT against the pegasusdb HPC accounting database; and open Request " +
				"Tracker tickets in allowlisted queues, metadata only. " +
				"Does NOT cover vulnerabilities or CVEs, user accounts, performance metrics or history, " +
				"ticket content or correspondence, or any file outside the policy's resource list. " +
				"Package history, patch level, log contents and configuration are covered ONLY where a " +
				"policy resource names the file -- check the resource list before refusing them; if a " +
				"resource exists for the question, use it. " +
				"Do not call this for questions it cannot answer.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"intent": map[string]any{
						"type":        "string",
						"enum":        intents,
						"description": "Which bounded question to ask.",
					},
					"host":     hostSchema(liveHosts),
					"resource": resourceSchema(liveResources),
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
					"owner": map[string]any{
						"type": "string",
						"description": "For tickets.open and tickets.for_host only: one Request Tracker owner login exactly " +
							"as evidence shows it (an @gwu.edu address), or Nobody for unowned tickets. One owner per " +
							"call. With an owner and no since, that owner's oldest tickets come first; add no until for that.",
					},
					"order": map[string]any{
						"type": "string",
						"enum": []string{broker.TicketOrderOldestFirst, broker.TicketOrderNewestFirst},
						"description": "For tickets.open and tickets.for_host only: which end of the matching tickets " +
							"a truncated page shows. Omit it and the bound decides (until: oldest first; since: newest " +
							"first). Set oldest_first for \"the oldest tickets created in the last N days\": since: Nd " +
							"with order: oldest_first.",
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
	return definition
}

// Session runs one question through the model, the broker, and back.
type Session struct {
	// agentOps is what each live host's agent reported it can do. A host
	// absent from the map was never probed, which is not the same as one that
	// offered nothing.
	agentOps map[string]agentCapabilities

	client   *MindRouterClient
	router   *broker.Router
	executor *connector.Executor
	intents  []string
	auditor  *Auditor
	model    string
	caller   string
	agent    string
	trace    []TraceEntry
	event    AuditEvent
	started  time.Time
	// evidence is every result that reached the model, for callers that want
	// the figures as data rather than retyped in prose.
	evidence []connector.Result
}

// WithAudit attaches an audit destination. Without one the session works but
// leaves no record.
func (s *Session) WithAudit(auditor *Auditor, model string) *Session {
	s.auditor = auditor
	s.model = model
	return s
}

// WithCaller records who asked and through which agent, for a service that
// answers for many people. Both are empty for a local askcass run.
func (s *Session) WithCaller(person, client string) *Session {
	s.caller = person
	s.agent = client
	return s
}

// Evidence returns every result the model was given while answering.
func (s *Session) Evidence() []connector.Result { return s.evidence }

// TraceEntry records one step of the loop so an operator can see exactly what
// the model proposed and what policy did with it.
type TraceEntry struct {
	Stage   string `json:"stage"`
	Detail  string `json:"detail"`
	Allowed bool   `json:"allowed"`
}

// NewSession wires a model client to a policy router and an executor.
//
// Only intents whose source the executor can reach are offered to the model.
// intentIsOffered enforces the same list.
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

// ReconcileAgents asks every live endpoint agent what it implements, so a
// request a host can't serve is refused with that host's real capability list
// instead of failing opaquely. It costs a round trip per host, so callers opt
// in; skipping it is safe, since "not probed" means "no opinion" downstream.
func (s *Session) ReconcileAgents(ctx context.Context) {
	hosts, _ := s.router.LiveTargets()
	s.agentOps = probeAgents(ctx, s.executor, hosts)
}

// Intents lists what this session can actually offer a model.
func (s *Session) Intents() []string { return s.intents }

// Trace returns the decisions made during the last Ask.
func (s *Session) Trace() []TraceEntry {
	return s.trace
}

// estimatedTokens is a deliberately pessimistic size for what will be sent:
// characters divided by the densest ratio measured, since there is no
// tokenizer here. It errs toward refusing early.
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

// roomForMore reports whether another payload of this size still fits the
// served context.
func roomForMore(messages []Message, tools []any, addition int) (int, bool) {
	projected := estimatedTokens(messages, tools) + int(float64(addition)/jsonCharsPerToken)
	return projected, projected <= servedContextTokens
}

// discloseWithheldEvidence appends the limitation when the model did not
// state it: a partial answer that doesn't say so reads as complete.
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

// Ask answers a question, letting the model work in up to maxToolCalls steps,
// so it can inspect a schema, query, and correct a rejected query. Every call
// is validated and authorized independently: more turns is more room to work,
// not more authority.
func (s *Session) Ask(ctx context.Context, question string) (string, error) {
	s.trace = nil
	s.evidence = nil
	s.started = time.Now()
	s.event = AuditEvent{
		RequestID: newRequestID(),
		Question:  question,
		Model:     s.model,
		Caller:    s.caller,
		Client:    s.agent,
		Decision:  "no_tool_call",
		Status:    "answered",
	}
	defer s.writeAudit()

	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: question},
	}
	// Built per session: it depends on this session's policy.
	liveHosts, liveResources := s.router.LiveTargets()
	tools := []any{toolDefinition(s.intents, liveHosts, liveResources)}

	forceTool := ""
	budgetReached := false

	// How the turns were spent, so a turn-limit failure can say whether the
	// model was exploring or repeating one failing query.
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

			// A model sometimes writes out the call it means to make and
			// stops. With turns left, force the call: the next turn names the
			// function in tool_choice, so a call is the only shape the
			// response can take.
			if describesACallInstead(answer) && turn < maxToolCalls-1 {
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
			// The documentation is consulted only when no call succeeded and
			// none failed, i.e. the model judged no source applied. With
			// evidence in hand, prose must not displace it; after a failure,
			// a fluent paragraph would hide the breakage.
			if succeeded == 0 && failed == 0 {
				if fromDocs, docErr := s.answerFromDocs(ctx, question); docErr == nil {
					s.record("answered_from_documentation",
						"no evidence source applied; answered from the embedded documentation", true)
					s.event.Decision = "documentation"
					s.event.Answer = fromDocs
					s.event.AnswerChars = len(fromDocs)
					return fromDocs, nil
				} else {
					// The model's own answer stands.
					s.record("documentation_lookup_failed", docErr.Error(), false)
				}
			}

			// If a result was withheld for context and the model didn't say
			// so, the answer says it anyway.
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

		// The model's arguments are untrusted on every turn: runOneCall
		// decodes them strictly and authorizes them before anything executes.
		messages = append(messages, Message{
			Role: "assistant", Content: choice.Message.Content, ToolCalls: choice.Message.ToolCalls,
		})

		result, failure := s.runOneCall(ctx, call)
		if failure != nil {
			// A refusal ends the loop only when nothing has been collected yet:
			// someone who asks for something forbidden should be told so.
			// After evidence has been collected, a refused follow-up call must
			// not discard it; the model answers from what it has and says
			// what it could not get. The broker still refused the call.
			if !failure.recoverable && succeeded == 0 {
				s.event.Decision = "denied"
				return "", failure.err
			}
			if !failure.recoverable {
				s.record("denied_after_evidence",
					"a later call was refused; answering from the evidence already collected", false)
			}
			failed++
			lastError = failure.err.Error()

			// Failed attempts are audited too: they are what a question runs
			// out of turns on.
			attemptedQuery := queryFromArguments(call.Function.Arguments)
			s.event.Calls = append(s.event.Calls, AuditCall{
				Source: "orchestrator",
				Action: "attempt_failed",
				Query:  attemptedQuery,
				Error:  lastError,
			})

			// Name a repeat instead of feeding back the same "correct this"
			// to a model that already made this mistake. Two signals: the same
			// query, or a different query with an error already seen (the
			// construction is wrong, not the spelling).
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
			// Traced, so an authorized call doesn't silently vanish.
			s.record("evidence_too_large",
				fmt.Sprintf("%d bytes exceeds the %d-byte per-result cap; the whole result was discarded, not truncated",
					len(evidenceJSON), evidenceBudget()), false)
			messages = append(messages, Message{
				Role: "tool", ToolCallID: call.ID, Name: toolName,
				Content: `{"error":"the result was too large to return; narrow it or aggregate in SQL"}`,
			})
			continue
		}

		// The per-result cap says nothing about the total: every result stays
		// in the history and is resent each turn. Withholding here gives an
		// answer that says what it is missing, rather than a gateway 400 or,
		// on an ollama backend, a request whose head was silently dropped.
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
		s.evidence = append(s.evidence, result)
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

	// Say how the turns were spent, not just that the limit was hit, so the
	// reader knows whether to fix the query, the source, or the limit.
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

	// The tool lists only reachable intents, but a model can name one it
	// wasn't offered. Refuse it here as a configuration fact rather than let
	// it fail in the executor as "no connector registered".
	if err := s.intentIsOffered(request.Intent); err != nil {
		s.record("intent_not_offered", err.Error(), false)
		if s.event.Decision == "no_tool_call" {
			s.event.Decision = "denied"
		}
		// Another attempt helps only if something else is reachable. When this
		// session can reach nothing, retrying spends turns to rediscover that.
		return connector.Result{}, &callFailure{err: err, recoverable: len(s.intents) > 0}
	}

	if err := ticketBoundContradiction(s.event.Question, request); err != nil {
		s.record("bound_contradicts_question", err.Error(), false)
		if s.event.Decision == "no_tool_call" {
			s.event.Decision = "denied"
		}
		return connector.Result{}, &callFailure{err: err, recoverable: true}
	}

	plan, err := s.router.Plan(request)
	if err != nil {
		s.record("policy_denied", err.Error(), false)
		// Record the denial even when the model gets another attempt.
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

	// Policy says the host offers the resource; the agent decides whether it
	// can serve it. Checking first turns an opaque failure, which a model
	// retries verbatim, into a refusal naming what the host does offer.
	if err := checkPlanAgainstAgents(plan, s.agentOps); err != nil {
		s.record("agent_lacks_operation", err.Error(), false)
		return connector.Result{}, &callFailure{err: err, recoverable: true}
	}

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
	s.event.Trace = s.trace
	if s.event.AnswerChars == 0 && s.event.Status == "answered" {
		s.event.Status = "failed"
		for _, entry := range s.trace {
			if !entry.Allowed {
				s.event.Error = entry.Stage + ": " + entry.Detail
			}
		}
	}
	if err := s.auditor.Record(s.event); err != nil {
		// Deliberately loud: a quietly failed audit invites the belief that a
		// record exists.
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
// (which the model may fix) rather than an authorization refusal (which is an
// answer; retrying would invite a search for a host that is authorized).
func isRetryableRouteError(err error) bool {
	var routeErr *broker.RouteError
	if !errors.As(err, &routeErr) {
		return false
	}
	switch routeErr.Code {
	case "invalid_request", "invalid_query", "invalid_since", "invalid_until", "missing_since",
		"invalid_limit", "invalid_match", "invalid_severity", "invalid_state",
		"invalid_host", "invalid_owner", "invalid_resource",
		"missing_host", "missing_resource", "unknown_intent":
		return true
	default:
		return false
	}
}

// describesACallInstead reports whether an answer looks like a tool call that
// was written out rather than issued. A heuristic: a false positive costs one
// turn, a false negative returns a plan instead of an answer.
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

// evidenceBudget is the largest single result this session hands the model.
// Raise it together with any connector cap, or a query succeeds and is then
// discarded.
func evidenceBudget() int {
	if value := env.Get("CASS_MAX_EVIDENCE"); value != "" {
		if size, err := strconv.Atoi(value); err == nil && size > 0 {
			return size
		}
	}
	return maxEvidenceJSON
}

// queryFromArguments pulls the SQL out of a tool call for the record, or
// returns the arguments verbatim when they don't parse.
func queryFromArguments(arguments string) string {
	var parsed struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal([]byte(arguments), &parsed); err != nil || parsed.Query == "" {
		return arguments
	}
	return parsed.Query
}

// normalizeQuery collapses whitespace and case so a re-sent query is
// recognised despite formatting. It does not attempt SQL equivalence.
func normalizeQuery(query string) string {
	return strings.ToLower(strings.Join(strings.Fields(query), " "))
}

// hostSchema names the hosts the policy authorizes for live evidence without
// closing the field, because host is not only a live-evidence selector.
func hostSchema(liveHosts []string) map[string]any {
	description := "Host selector. Required for agent.status, live.evidence, and tickets.for_host."
	if len(liveHosts) > 0 {
		description += " Hosts authorized for live.evidence, which must be given exactly as written: " +
			strings.Join(liveHosts, ", ") + "."
	}
	return map[string]any{"type": "string", "description": description}
}

// resourceSchema closes the field to the aliases the policy defines. With none
// it stays open (an empty enum permits nothing); live.evidence is withheld
// entirely in that case anyway.
func resourceSchema(liveResources []string) map[string]any {
	schema := map[string]any{
		"type":        "string",
		"description": "Policy-defined resource alias. For live.evidence ONLY. Never put SQL here. Not a path.",
	}
	if len(liveResources) > 0 {
		schema["enum"] = liveResources
		schema["description"] = "Policy-defined resource alias, not a filesystem path. " +
			"For live.evidence ONLY. Never put SQL here."
	}
	return schema
}

// intentIsOffered reports whether this session advertised the intent, naming
// what it did advertise when it did not.
//
// NewSession decides what the model is told exists; this decides what it may
// actually ask for.
func (s *Session) intentIsOffered(intent broker.Intent) error {
	for _, offered := range s.intents {
		if offered == string(intent) {
			return nil
		}
	}
	if len(s.intents) == 0 {
		return fmt.Errorf("this deployment has no evidence sources configured, so no intent can be "+
			"served, including %q. That is a configuration problem on the host running the broker, "+
			"not something a different request can work around", intent)
	}
	return fmt.Errorf("intent %q was not offered by this deployment and cannot be served. "+
		"Its source is not configured here. Available: %s",
		intent, strings.Join(s.intents, ", "))
}
