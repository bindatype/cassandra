package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// supportedProtocols are the MCP revisions this server speaks, newest first.
var supportedProtocols = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

const toolName = "cass_ask"

// Answer is one question's result: Cassandra's prose plus the evidence it was
// given, so a client can read figures as data instead of parsing sentences.
type Answer struct {
	Text     string          `json:"answer"`
	Evidence json.RawMessage `json:"evidence"`
}

// Runner answers one question as one person. The real one runs cass-chat.
type Runner func(ctx context.Context, caller Caller, question string) (Answer, error)

// Caller is an authenticated, allowlisted person and the agent they use.
type Caller struct {
	Person string
	Token  string
	Client string
}

// Validator reports whether MindRouter accepts a token.
type Validator func(ctx context.Context, token string) (bool, error)

type Server struct {
	allowlist   *Allowlist
	validate    Validator
	run         Runner
	maxInflight int
	maxPerUser  int
	log         io.Writer

	mu        sync.Mutex
	inflight  int
	perPerson map[string]int
	sessions  map[string]session // by Mcp-Session-Id
	valid     map[string]time.Time
}

func NewServer(allowlist *Allowlist, validate Validator, run Runner, maxInflight, maxPerUser int, log io.Writer) *Server {
	return &Server{
		allowlist: allowlist, validate: validate, run: run,
		maxInflight: maxInflight, maxPerUser: maxPerUser, log: log,
		perPerson: map[string]int{}, sessions: map[string]session{}, valid: map[string]time.Time{},
	}
}

// tokenCacheTTL bounds how long a revoked MindRouter key keeps working here.
const tokenCacheTTL = 60 * time.Second

// sessionIdleTTL is how long an unused session is remembered. Many clients
// reconnect without the DELETE that ends a session, so without it the map
// grows for the life of the process. A session only names the client in the
// log, so forgetting one costs nothing but that name.
const sessionIdleTTL = 24 * time.Hour

type session struct {
	client string
	seen   time.Time
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}
	caller, status, reason := s.authenticate(r)
	if status != http.StatusOK {
		w.Header().Set("WWW-Authenticate", `Bearer realm="cassandra"`)
		http.Error(w, reason, status)
		fmt.Fprintf(s.log, "%s refused %d %s\n", time.Now().UTC().Format(time.RFC3339), status, reason)
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.handleRPC(w, r, caller)
	case http.MethodDelete:
		s.mu.Lock()
		delete(s.sessions, r.Header.Get("Mcp-Session-Id"))
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	default:
		// No server-initiated messages, so no event stream to open.
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// authenticate checks the allowlist before MindRouter, so a token from someone
// outside the IT team costs no outbound call.
func (s *Server) authenticate(r *http.Request) (Caller, int, string) {
	header := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(header, "Bearer ")
	token = strings.TrimSpace(token)
	if !ok || token == "" {
		return Caller{}, http.StatusUnauthorized, "send your MindRouter API key as Authorization: Bearer <key>"
	}
	person, ok := s.allowlist.Lookup(token)
	if !ok {
		return Caller{}, http.StatusForbidden, "this MindRouter key is not on Cassandra's allowlist"
	}
	hash := TokenHash(token)
	s.mu.Lock()
	until, cached := s.valid[hash]
	s.mu.Unlock()
	if !cached || time.Now().After(until) {
		valid, err := s.validate(r.Context(), token)
		if err != nil {
			return Caller{}, http.StatusBadGateway, "could not reach MindRouter to check the key"
		}
		if !valid {
			return Caller{}, http.StatusUnauthorized, "MindRouter does not accept this key (revoked or mistyped)"
		}
		s.mu.Lock()
		s.valid[hash] = time.Now().Add(tokenCacheTTL)
		s.mu.Unlock()
	}
	return Caller{Person: person, Token: token}, http.StatusOK, ""
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request, caller Caller) {
	var req rpcRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		writeRPC(w, nil, nil, &rpcError{Code: -32600, Message: "expected one JSON-RPC 2.0 request"})
		return
	}
	if len(req.ID) == 0 {
		// A notification (notifications/initialized and the like) gets no reply.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	caller.Client = s.touchSession(r.Header.Get("Mcp-Session-Id"))
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"clientInfo"`
		}
		json.Unmarshal(req.Params, &params)
		version := supportedProtocols[0]
		for _, v := range supportedProtocols {
			if v == params.ProtocolVersion {
				version = v
			}
		}
		id := newSessionID()
		client := strings.TrimSpace(params.ClientInfo.Name + " " + params.ClientInfo.Version)
		now := time.Now()
		s.mu.Lock()
		for old, sess := range s.sessions {
			if now.Sub(sess.seen) > sessionIdleTTL {
				delete(s.sessions, old)
			}
		}
		s.sessions[id] = session{client: client, seen: now}
		s.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", id)
		writeRPC(w, req.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "cassandra", "version": "1"},
			"instructions":    instructions,
		}, nil)
	case "ping":
		writeRPC(w, req.ID, map[string]any{}, nil)
	case "tools/list":
		writeRPC(w, req.ID, map[string]any{"tools": []any{askTool()}}, nil)
	case "tools/call":
		writeRPC(w, req.ID, s.callTool(r.Context(), caller, req.Params), nil)
	default:
		writeRPC(w, req.ID, nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method})
	}
}

// touchSession marks a session used and returns its client name, or "" for
// an unknown or expired one.
func (s *Server) touchSession(id string) string {
	if id == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return ""
	}
	sess.seen = time.Now()
	s.sessions[id] = sess
	return sess.client
}

func (s *Server) callTool(ctx context.Context, caller Caller, raw json.RawMessage) map[string]any {
	var params struct {
		Name      string `json:"name"`
		Arguments struct {
			Question string `json:"question"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil || params.Name != toolName {
		return toolError("unknown tool; the only tool is " + toolName)
	}
	question := strings.TrimSpace(params.Arguments.Question)
	if question == "" {
		return toolError("question is required")
	}
	if len(question) > 4000 {
		return toolError("question is longer than 4000 characters; ask something narrower")
	}
	release, busy := s.acquire(caller.Person)
	if busy != "" {
		return toolError(busy)
	}
	defer release()

	started := time.Now()
	answer, err := s.run(ctx, caller, question)
	outcome := "answered"
	if err != nil {
		outcome = "failed: " + err.Error()
	}
	fmt.Fprintf(s.log, "%s %s via %q %.1fs %s\n", started.UTC().Format(time.RFC3339), caller.Person,
		caller.Client, time.Since(started).Seconds(), outcome)
	if err != nil {
		return toolError(err.Error())
	}
	return map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": answer.Text}},
		"structuredContent": answer,
		"isError":           false,
	}
}

// acquire takes a slot, refusing rather than queueing: a refusal says why,
// a queue just looks slow.
func (s *Server) acquire(person string) (func(), string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perPerson[person] >= s.maxPerUser {
		return nil, fmt.Sprintf("you already have %d questions running; wait for one to finish", s.perPerson[person])
	}
	if s.inflight >= s.maxInflight {
		return nil, fmt.Sprintf("Cassandra is answering %d questions already; try again shortly", s.inflight)
	}
	s.inflight++
	s.perPerson[person]++
	return func() {
		s.mu.Lock()
		s.inflight--
		s.perPerson[person]--
		s.mu.Unlock()
	}, ""
}

func toolError(message string) map[string]any {
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": message}},
		"isError": true,
	}
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result any, rpcErr *rpcError) {
	w.Header().Set("Content-Type", "application/json")
	body := map[string]any{"jsonrpc": "2.0", "id": id}
	if id == nil {
		body["id"] = nil
	}
	if rpcErr != nil {
		body["error"] = rpcErr
	} else {
		body["result"] = result
	}
	json.NewEncoder(w).Encode(body)
}

func newSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

const instructions = "Cassandra answers questions about GW RTS infrastructure from live, read-only sources " +
	"and says which source each answer came from. Results are internal GW IT data, subject to GW data policy."

func askTool() map[string]any {
	return map[string]any{
		"name": toolName,
		"description": "Ask Cassandra, GW RTS's read-only infrastructure evidence service, one question in plain " +
			"English. It covers Zabbix problems and event history, Wazuh agent inventory, Request Tracker tickets " +
			"(metadata only, no requester), Slurm job accounting on Pegasus, and policy-approved reads from " +
			"managed hosts. Returns Cassandra's answer, which names its sources and limits, and the evidence as " +
			"JSON with figures counted by the source systems; quote figures from the evidence rather than " +
			"computing your own. One host or one ticket owner per question; for several, ask once each. " +
			"Results are internal GW IT data, subject to GW data policy.",
		"inputSchema": map[string]any{
			"type":                 "object",
			"properties":           map[string]any{"question": map[string]any{"type": "string", "description": "The question, in plain English."}},
			"required":             []string{"question"},
			"additionalProperties": false,
		},
	}
}

// TokenHash is how a key appears on the allowlist: never the key itself.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Allowlist maps key hashes to people, re-read when the file changes so a
// person can be added or removed without restarting the service.
type Allowlist struct {
	path    string
	mu      sync.Mutex
	modTime time.Time
	entries map[string]string
}

func NewAllowlist(path string) (*Allowlist, error) {
	a := &Allowlist{path: path}
	if err := a.reload(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Allowlist) Lookup(token string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if info, err := os.Stat(a.path); err == nil && !info.ModTime().Equal(a.modTime) {
		a.reloadLocked()
	}
	person, ok := a.entries[TokenHash(token)]
	return person, ok
}

func (a *Allowlist) reload() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reloadLocked()
}

// reloadLocked keeps the previous entries if the file cannot be read, so a
// half-written edit never locks everyone out mid-question.
func (a *Allowlist) reloadLocked() error {
	file, err := os.Open(a.path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	entries, err := parseAllowlist(file)
	if err != nil {
		return fmt.Errorf("%s: %w", a.path, err)
	}
	a.entries, a.modTime = entries, info.ModTime()
	return nil
}

func parseAllowlist(r io.Reader) (map[string]string, error) {
	entries := map[string]string{}
	scanner := bufio.NewScanner(r)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "sha256:") || len(fields[0]) != len("sha256:")+64 {
			return nil, fmt.Errorf("line %d: want \"sha256:<64 hex> person\"", n)
		}
		entries[fields[0]] = strings.Join(fields[1:], " ")
	}
	return entries, scanner.Err()
}

// MindRouterValidator checks a key the cheapest way MindRouter offers: list
// models, which answers 200 for a valid key and 401 otherwise.
func MindRouterValidator(endpoint string, client *http.Client) Validator {
	return func(ctx context.Context, token string) (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/v1/models", nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			return true, nil
		case http.StatusUnauthorized, http.StatusForbidden:
			return false, nil
		}
		return false, errors.New("MindRouter answered " + resp.Status)
	}
}
