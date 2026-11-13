package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Record is one request. Everything in here is something I have needed at least
// once while working out why a bill looked wrong or why a caller was getting
// 429s.
type Record struct {
	TS         string   `json:"ts"`
	ID         string   `json:"id"`
	Key        string   `json:"key"`
	Model      string   `json:"model"`
	Status     int      `json:"status"`
	Stream     bool     `json:"stream"`
	Prompt     int64    `json:"prompt_tokens"`
	Completion int64    `json:"completion_tokens"`
	LatencyMS  int64    `json:"latency_ms"`
	Injection  int      `json:"injection_score"`
	Hits       []string `json:"injection_hits,omitempty"`
	Verdict    string   `json:"verdict"`
	Redactions int      `json:"redactions"`
	IP         string   `json:"ip"`
	Err        string   `json:"error,omitempty"`
}

// Logger writes newline-delimited JSON. One writer, one file, no rotation.
// Point it at a pipe or a log shipper if you want history longer than a disk.
type Logger struct {
	mu  sync.Mutex
	f   *os.File
	tag string
}

func Open(path, tag string) (*Logger, error) {
	if path == "-" {
		return &Logger{f: os.Stdout, tag: tag}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f, tag: tag}, nil
}

func (l *Logger) Write(r Record) {
	if r.TS == "" {
		r.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(r)
	if err != nil {
		return
	}
	l.mu.Lock()
	l.f.Write(append(line, '\n'))
	l.mu.Unlock()
}

// Close is called once at shutdown. Failures here are not worth reporting: the
// process is going away and there is nothing left to do about it.
func (l *Logger) Close() {
	if l.f == nil || l.f == os.Stdout {
		return
	}
	l.mu.Lock()
	l.f.Close()
	l.mu.Unlock()
}

func (l *Logger) Tag() string { return l.tag }

func (l *Logger) Eventf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s: "+format+"\n", append([]any{l.tag}, args...)...)
}
