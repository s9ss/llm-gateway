package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/s9ss/llm-gateway/internal/audit"
	"github.com/s9ss/llm-gateway/internal/config"
	"github.com/s9ss/llm-gateway/internal/guard"
	"github.com/s9ss/llm-gateway/internal/keys"
)

const (
	// A completion longer than this is not a completion, it is a download.
	maxResponseBytes = 8 << 20
	// Rough. English prose and code land near four bytes per token; JSON and
	// minified text drift from that. Only used when the upstream omits usage.
	bytesPerToken = 4
)

type Server struct {
	cfg    *config.Config
	store  *keys.Store
	log    *audit.Logger
	client *http.Client
	up     *url.URL
}

func New(cfg *config.Config, store *keys.Store, logger *audit.Logger) (*Server, error) {
	up, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		// No ProxyFromEnvironment on purpose: an attacker who can set HTTP_PROXY
		// in the environment would otherwise get every upstream key.
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   16,
		ForceAttemptHTTP2:     true,
	}
	return &Server{
		cfg:   cfg,
		store: store,
		log:   logger,
		up:    up,
		client: &http.Client{
			Transport: transport,
			Timeout:   0, // the per-request context carries the deadline
		},
	}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/__gw/") {
		s.admin(w, r)
		return
	}
	s.handleProxy(w, r)
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := audit.Record{ID: newID(), IP: clientIP(r), Verdict: "forwarded"}

	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "only POST is proxied")
		return
	}

	secret, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing bearer token")
		return
	}

	entry, err := s.store.Lookup(secret)
	if err != nil {
		rec.Status = http.StatusUnauthorized
		rec.Verdict = "unknown_key"
		s.log.Write(rec)
		writeErr(w, http.StatusUnauthorized, "unknown key")
		return
	}
	rec.Key = entry.Name

	body, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBytes+1))
	if err != nil {
		rec.Status = http.StatusBadRequest
		rec.Verdict = "read_error"
		rec.Err = err.Error()
		s.log.Write(rec)
		writeErr(w, http.StatusBadRequest, "could not read request body")
		return
	}
	if int64(len(body)) > s.cfg.MaxBodyBytes {
		rec.Status = http.StatusRequestEntityTooLarge
		rec.Verdict = "body_too_large"
		s.log.Write(rec)
		writeErr(w, http.StatusRequestEntityTooLarge, "request body over max_body_bytes")
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		rec.Status = http.StatusBadRequest
		rec.Verdict = "bad_json"
		rec.Err = err.Error()
		s.log.Write(rec)
		writeErr(w, http.StatusBadRequest, "request body is not a JSON object")
		return
	}

	model, _ := payload["model"].(string)
	rec.Model = model
	if model == "" {
		rec.Status = http.StatusBadRequest
		rec.Verdict = "no_model"
		s.log.Write(rec)
		writeErr(w, http.StatusBadRequest, "model field is required")
		return
	}
	if !allowed(s.cfg.Models, model) {
		rec.Status = http.StatusForbidden
		rec.Verdict = "model_not_in_allowlist"
		s.log.Write(rec)
		writeErr(w, http.StatusForbidden, "model "+model+" is not in the gateway allowlist")
		return
	}

	if err := s.store.Admit(entry, model, time.Now()); err != nil {
		rec.Status = http.StatusTooManyRequests
		switch {
		case errors.Is(err, keys.ErrModelDeny):
			rec.Status = http.StatusForbidden
			rec.Verdict = "model_denied_for_key"
		case errors.Is(err, keys.ErrRate):
			rec.Verdict = "rate_limited"
		case errors.Is(err, keys.ErrBudget):
			rec.Verdict = "budget_exhausted"
		}
		s.log.Write(rec)
		writeErr(w, rec.Status, err.Error())
		return
	}

	if clampTokens(payload, s.cfg.MaxTokens) {
		if err := reencode(payload, &body); err != nil {
			rec.Status = http.StatusInternalServerError
			rec.Verdict = "reencode_failed"
			s.log.Write(rec)
			writeErr(w, http.StatusInternalServerError, "could not normalise request")
			return
		}
	}

	text := guard.Text(payload)
	score, hits := guard.Score(text)
	rec.Injection = score
	rec.Hits = hits
	if score > 0 && s.cfg.InjectionAction == "block" {
		rec.Status = http.StatusBadRequest
		rec.Verdict = "injection_blocked"
		s.log.Write(rec)
		writeErr(w, http.StatusBadRequest, "request blocked: prompt injection heuristics fired")
		return
	}
	if score > 0 {
		rec.Verdict = "injection_flagged"
	}

	stream, _ := payload["stream"].(bool)
	rec.Stream = stream

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Timeout)
	defer cancel()

	target := *s.up
	target.Path = joinPath(s.up.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		rec.Status = http.StatusInternalServerError
		rec.Verdict = "build_failed"
		s.log.Write(rec)
		writeErr(w, http.StatusInternalServerError, "could not build upstream request")
		return
	}
	// Built from scratch, not copied. Whatever the client sent in these headers
	// does not travel any further than this line.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.cfg.UpstreamKey)
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	} else if stream {
		req.Header.Set("Accept", "text/event-stream")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		rec.Status = http.StatusBadGateway
		rec.Verdict = "upstream_error"
		rec.Err = err.Error()
		rec.LatencyMS = time.Since(start).Milliseconds()
		s.log.Write(rec)
		writeErr(w, http.StatusBadGateway, "upstream request failed")
		return
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		w.Header().Set("Cache-Control", cc)
	}

	if stream || strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		rec.Status = resp.StatusCode
		rec.Prompt = int64(estimate(len(text)))
		s.pipe(w, resp.Body, &rec, start, entry)
		return
	}

	out, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		rec.Status = http.StatusBadGateway
		rec.Verdict = "upstream_read_error"
		rec.Err = err.Error()
		rec.LatencyMS = time.Since(start).Milliseconds()
		s.log.Write(rec)
		writeErr(w, http.StatusBadGateway, "upstream response was cut short")
		return
	}

	clean, n := guard.Redact(out)
	rec.Redactions = n

	rec.Status = resp.StatusCode
	rec.Prompt, rec.Completion = usage(clean, len(text), len(out))
	s.store.Charge(entry, rec.Prompt+rec.Completion)
	rec.LatencyMS = time.Since(start).Milliseconds()

	w.WriteHeader(resp.StatusCode)
	w.Write(clean)
	s.log.Write(rec)
}

// pipe forwards an event stream untouched. Redaction is deliberately not applied
// here: buffering a stream to scan it defeats the point of streaming, and the
// client would rather have tokens on time. If you need scanned streams, buffer
// and accept the latency.
func (s *Server) pipe(w http.ResponseWriter, body io.Reader, rec *audit.Record, start time.Time, entry *keys.Entry) {
	flusher, _ := w.(http.Flusher)
	w.WriteHeader(rec.Status)
	if flusher != nil {
		flusher.Flush()
	}

	buf := make([]byte, 16<<10)
	var written int
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				rec.Verdict = "client_gone"
				break
			}
			written += n
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				rec.Verdict = "stream_interrupted"
				rec.Err = err.Error()
			}
			break
		}
	}

	rec.Completion = int64(estimate(written))
	s.store.Charge(entry, rec.Prompt+rec.Completion)
	rec.LatencyMS = time.Since(start).Milliseconds()
	s.log.Write(*rec)
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r.RemoteAddr) {
		// Key names and spend are not public. Loopback only, no exceptions.
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/__gw/health":
		json.NewEncoder(w).Encode(map[string]any{
			"ok":       true,
			"build":    s.log.Tag(),
			"upstream": s.up.Host,
			"uptime_s": int(time.Since(booted).Seconds()),
		})
	case "/__gw/stats":
		json.NewEncoder(w).Encode(map[string]any{
			"keys": s.store.Snapshot(time.Now()),
		})
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

var booted = time.Now()

func usage(resp []byte, promptFallback, completionFallback int) (int64, int64) {
	var env struct {
		Usage *struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			InputTokens      int64 `json:"input_tokens"`
			OutputTokens     int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(resp, &env); err == nil && env.Usage != nil {
		p := env.Usage.PromptTokens + env.Usage.InputTokens
		c := env.Usage.CompletionTokens + env.Usage.OutputTokens
		if p > 0 || c > 0 {
			return p, c
		}
	}
	return int64(estimate(promptFallback)), int64(estimate(completionFallback))
}

func estimate(n int) int {
	if n <= 0 {
		return 0
	}
	return n/bytesPerToken + 1
}

func clampTokens(payload map[string]any, max int) bool {
	changed := false
	for _, field := range []string{"max_tokens", "max_completion_tokens"} {
		v, ok := payload[field]
		if !ok {
			continue
		}
		f, ok := v.(float64)
		if !ok || f <= float64(max) {
			continue
		}
		payload[field] = float64(max)
		changed = true
	}
	return changed
}

func reencode(payload map[string]any, dst *[]byte) error {
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	*dst = buf
	return nil
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func isLoopback(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func allowed(list []string, model string) bool {
	for _, m := range list {
		if m == model {
			return true
		}
	}
	return false
}

func joinPath(base, add string) string {
	switch {
	case base == "":
		return add
	case strings.HasSuffix(base, "/") && strings.HasPrefix(add, "/"):
		return base + add[1:]
	case !strings.HasSuffix(base, "/") && !strings.HasPrefix(add, "/"):
		return base + "/" + add
	}
	return base + add
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": msg, "type": "gateway_error", "code": code},
	})
}
