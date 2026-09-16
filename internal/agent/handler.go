package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type Handler struct {
	service *Service
	cfg     Config
}

type requestContextKey string

const callerIDContextKey requestContextKey = "caller_id"

func NewHandler(service *Service, cfg Config) http.Handler {
	handler := &Handler{
		service: service,
		cfg:     cfg,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handler.handleHealth)
	mux.Handle("/v1/capabilities", handler.requireBearerAuth(http.HandlerFunc(handler.handleCapabilities)))
	mux.Handle("/v1/operations", handler.requireBearerAuth(http.HandlerFunc(handler.handleOperations)))
	return mux
}

func (h *Handler) requireBearerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		callerID, authenticated := h.authenticateToken(token)
		if !ok || !authenticated {
			w.Header().Set("WWW-Authenticate", `Bearer realm="cass"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"status": "error",
				"error": map[string]string{
					"code":    "unauthorized",
					"message": "missing or invalid bearer token",
				},
			})
			return
		}
		ctx := context.WithValue(r.Context(), callerIDContextKey, callerID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

func (h *Handler) authenticateToken(candidate string) (string, bool) {
	matched := 0
	callerID := ""
	for _, expected := range h.cfg.AuthTokens {
		equal := subtle.ConstantTimeCompare([]byte(candidate), []byte(expected))
		matched |= equal
		if equal == 1 {
			callerID = credentialID(expected)
		}
	}
	return callerID, matched == 1
}

func credentialID(token string) string {
	digest := sha256.Sum256([]byte(token))
	return "token:" + hex.EncodeToString(digest[:8])
}

func callerIDFromRequest(r *http.Request) string {
	callerID, _ := r.Context().Value(callerIDContextKey).(string)
	return callerID
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"agent":   agentName,
		"version": agentVersion,
	})
}

func (h *Handler) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	start := time.Now()
	requestID := newRequestID()
	if !h.service.operationEnabled(operationCapabilitiesDescribe) {
		message := "operation is disabled by agent policy"
		event := AuditEvent{
			RequestID:  requestID,
			Operation:  operationCapabilitiesDescribe,
			Status:     "error",
			Code:       "operation_disabled",
			Message:    message,
			DurationMS: time.Since(start).Milliseconds(),
			RemoteAddr: r.RemoteAddr,
			CallerID:   callerIDFromRequest(r),
		}
		if !h.recordAudit(w, event) {
			return
		}
		writeJSON(w, http.StatusForbidden, ResponseEnvelope{
			RequestID: requestID,
			Operation: operationCapabilitiesDescribe,
			Status:    "error",
			Metadata: ResponseMeta{
				Timestamp:  start.UTC().Format(time.RFC3339Nano),
				DurationMS: event.DurationMS,
				Agent:      agentName,
				Version:    agentVersion,
			},
			Error: &ErrorPayload{Code: event.Code, Message: message},
		})
		return
	}

	capabilities := h.service.Capabilities()
	event := AuditEvent{
		RequestID:  requestID,
		Operation:  operationCapabilitiesDescribe,
		Status:     "ok",
		DurationMS: time.Since(start).Milliseconds(),
		RemoteAddr: r.RemoteAddr,
		CallerID:   callerIDFromRequest(r),
	}
	if !h.recordAudit(w, event) {
		return
	}
	writeJSON(w, http.StatusOK, capabilities)
}

func (h *Handler) handleOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req RequestEnvelope
	if err := h.decodeRequest(w, r, &req); err != nil {
		statusCode := http.StatusBadRequest
		code := "invalid_json"
		message := "request body must contain exactly one valid JSON value"
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			statusCode = http.StatusRequestEntityTooLarge
			code = "request_too_large"
			message = fmt.Sprintf("request body exceeds %d bytes", h.cfg.MaxRequestBytes)
		}
		h.writeRequestError(w, r, req, statusCode, code, message)
		return
	}

	resp, statusCode := h.service.Execute(r.Context(), req)
	event := AuditEvent{
		RequestID:  resp.RequestID,
		Operation:  req.Operation,
		Status:     resp.Status,
		DurationMS: resp.Metadata.DurationMS,
		RemoteAddr: r.RemoteAddr,
		CallerID:   callerIDFromRequest(r),
		TargetPath: auditTargetPath(req),
		Metadata:   auditMetadata(req, h.cfg),
		Code:       errorCode(resp.Error),
		Message:    errorMessage(resp.Error),
	}
	if !h.recordAudit(w, event) {
		return
	}
	writeJSON(w, statusCode, resp)
}

func (h *Handler) decodeRequest(w http.ResponseWriter, r *http.Request, req *RequestEnvelope) error {
	body := http.MaxBytesReader(w, r.Body, h.cfg.MaxRequestBytes)
	defer body.Close()

	decoder := json.NewDecoder(body)
	if err := decoder.Decode(req); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body contains multiple JSON values")
		}
		return err
	}
	return nil
}

func (h *Handler) writeRequestError(
	w http.ResponseWriter,
	r *http.Request,
	req RequestEnvelope,
	statusCode int,
	code string,
	message string,
) {
	resp := ResponseEnvelope{
		RequestID: newRequestID(),
		Operation: req.Operation,
		Status:    "error",
		Metadata: ResponseMeta{
			Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
			DurationMS: 0,
			Truncated:  false,
			Agent:      agentName,
			Version:    agentVersion,
		},
		Error: &ErrorPayload{
			Code:    code,
			Message: message,
		},
	}
	event := AuditEvent{
		RequestID:  resp.RequestID,
		Operation:  req.Operation,
		Status:     "error",
		Code:       code,
		Message:    message,
		DurationMS: 0,
		RemoteAddr: r.RemoteAddr,
		CallerID:   callerIDFromRequest(r),
		TargetPath: auditTargetPath(req),
	}
	if !h.recordAudit(w, event) {
		return
	}
	writeJSON(w, statusCode, resp)
}

func (h *Handler) recordAudit(w http.ResponseWriter, event AuditEvent) bool {
	var err error
	if h.service.auditor == nil {
		err = errors.New("audit recorder is not configured")
	} else {
		err = h.service.auditor.Record(event)
	}
	if err == nil {
		return true
	}

	log.Printf("audit record failed request_id=%s operation=%s: %v", event.RequestID, event.Operation, err)
	writeJSON(w, http.StatusServiceUnavailable, ResponseEnvelope{
		RequestID: event.RequestID,
		Operation: event.Operation,
		Status:    "error",
		Metadata: ResponseMeta{
			Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
			DurationMS: event.DurationMS,
			Truncated:  false,
			Agent:      agentName,
			Version:    agentVersion,
		},
		Error: &ErrorPayload{
			Code:    "audit_unavailable",
			Message: "request result withheld because the audit record could not be written",
		},
	})
	return false
}

func auditTargetPath(req RequestEnvelope) string {
	switch req.Operation {
	case operationFilesystemList, operationFilesystemStat, operationFilesystemRead, operationFilesystemTail:
		var target pathTarget
		if err := json.Unmarshal(req.Target, &target); err == nil {
			return target.Path
		}
	}
	return ""
}

func auditMetadata(req RequestEnvelope, cfg Config) map[string]any {
	switch req.Operation {
	case operationFilesystemList, operationFilesystemStat, operationFilesystemRead, operationFilesystemTail:
		return map[string]any{"allowed_roots": cfg.AllowedRoots}
	default:
		return nil
	}
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func newRequestID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "req_fallback"
	}
	return "req_" + hex.EncodeToString(raw[:])
}

func errorCode(err *ErrorPayload) string {
	if err == nil {
		return ""
	}
	return err.Code
}

func errorMessage(err *ErrorPayload) string {
	if err == nil {
		return ""
	}
	return err.Message
}
