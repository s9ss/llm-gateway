package keys

import (
	"errors"
	"sync"
	"time"

	"github.com/s9ss/llm-gateway/internal/config"
)

var (
	ErrUnknown   = errors.New("unknown key")
	ErrRate      = errors.New("request rate exceeded")
	ErrBudget    = errors.New("daily token budget exhausted")
	ErrModelDeny = errors.New("model not permitted for this key")
)

type Entry struct {
	Name        string
	Secret      string
	DailyTokens int64
	RPM         int
	Models      map[string]bool
}

// In-memory only. Everything resets on restart, which is fine for one instance
// and wrong the moment you run two.
type Store struct {
	mu       sync.Mutex
	bySecret map[string]*Entry
	day      string
	used     map[string]int64
	window   map[string][]time.Time
}

func New(cfgs []config.Key) *Store {
	s := &Store{
		bySecret: make(map[string]*Entry, len(cfgs)),
		used:     make(map[string]int64, len(cfgs)),
		window:   make(map[string][]time.Time, len(cfgs)),
		day:      today(time.Now()),
	}
	for _, c := range cfgs {
		models := make(map[string]bool, len(c.Models))
		for _, m := range c.Models {
			models[m] = true
		}
		s.bySecret[c.Secret] = &Entry{
			Name:        c.Name,
			Secret:      c.Secret,
			DailyTokens: c.DailyTokens,
			RPM:         c.RPM,
			Models:      models,
		}
	}
	return s
}

func (s *Store) Lookup(secret string) (*Entry, error) {
	e, ok := s.bySecret[secret]
	if !ok {
		return nil, ErrUnknown
	}
	return e, nil
}

// Admit checks the budget but does not reserve against it. The real token count
// is only known after the upstream answers, so a request that starts under
// budget can push the key over it and the next one gets refused.
func (s *Store) Admit(e *Entry, model string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(e.Models) > 0 && !e.Models[model] {
		return ErrModelDeny
	}

	if d := today(now); d != s.day {
		s.day = d
		s.used = make(map[string]int64, len(s.used))
	}

	cutoff := now.Add(-time.Minute)
	recent := s.window[e.Name][:0]
	for _, t := range s.window[e.Name] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= e.RPM {
		s.window[e.Name] = recent
		return ErrRate
	}
	s.window[e.Name] = append(recent, now)

	if s.used[e.Name] >= e.DailyTokens {
		return ErrBudget
	}
	return nil
}

func (s *Store) Charge(e *Entry, tokens int64) {
	if tokens <= 0 {
		return
	}
	s.mu.Lock()
	s.used[e.Name] += tokens
	s.mu.Unlock()
}

type Snapshot struct {
	Name        string `json:"name"`
	Used        int64  `json:"tokens_used_today"`
	Budget      int64  `json:"tokens_per_day"`
	Remaining   int64  `json:"tokens_remaining"`
	RequestsMin int    `json:"requests_last_minute"`
}

func (s *Store) Snapshot(now time.Time) []Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := now.Add(-time.Minute)
	out := make([]Snapshot, 0, len(s.bySecret))
	for _, e := range s.bySecret {
		used := s.used[e.Name]
		remaining := e.DailyTokens - used
		if remaining < 0 {
			remaining = 0
		}
		n := 0
		for _, t := range s.window[e.Name] {
			if t.After(cutoff) {
				n++
			}
		}
		out = append(out, Snapshot{
			Name:        e.Name,
			Used:        used,
			Budget:      e.DailyTokens,
			Remaining:   remaining,
			RequestsMin: n,
		})
	}
	return out
}

func today(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}
