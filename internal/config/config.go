package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Key is one caller. The secret is what the client sends in the Authorization
// header; the upstream key never leaves this process.
type Key struct {
	Name        string   `json:"name"`
	Secret      string   `json:"secret"`
	DailyTokens int64    `json:"daily_tokens"`
	RPM         int      `json:"requests_per_minute"`
	Models      []string `json:"models"`
}

type Config struct {
	Listen          string   `json:"listen"`
	Upstream        string   `json:"upstream"`
	UpstreamKey     string   `json:"upstream_key"`
	UpstreamKeyFile string   `json:"upstream_key_file"`
	Models          []string `json:"models"`
	MaxBodyBytes    int64    `json:"max_body_bytes"`
	MaxTokens       int      `json:"max_tokens"`
	TimeoutSeconds  int      `json:"timeout_seconds"`
	InjectionAction string   `json:"injection_action"`
	AuditPath       string   `json:"audit_path"`
	Keys            []Key    `json:"keys"`

	Timeout time.Duration `json:"-"`
}

const (
	// 32 KiB is plenty for a chat payload and small enough that a stuck client
	// cannot make us hold a large buffer.
	defaultMaxBody = 1 << 15
	defaultTimeout = 120
)

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Editors on Windows still save with a BOM, and encoding/json chokes on it.
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})

	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = defaultMaxBody
	}
	if c.MaxTokens == 0 {
		c.MaxTokens = 4096
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = defaultTimeout
	}
	if c.InjectionAction == "" {
		c.InjectionAction = "flag"
	}
	if c.AuditPath == "" {
		c.AuditPath = "audit.jsonl"
	}
	c.Timeout = time.Duration(c.TimeoutSeconds) * time.Second
}

func (c *Config) validate() error {
	if c.UpstreamKey == "" && c.UpstreamKeyFile == "" {
		return fmt.Errorf("upstream_key or upstream_key_file is required")
	}
	if c.UpstreamKeyFile != "" {
		raw, err := os.ReadFile(c.UpstreamKeyFile)
		if err != nil {
			return fmt.Errorf("read upstream_key_file: %w", err)
		}
		c.UpstreamKey = strings.TrimSpace(string(raw))
		if c.UpstreamKey == "" {
			return fmt.Errorf("upstream_key_file %s is empty", c.UpstreamKeyFile)
		}
	}

	u, err := url.Parse(c.Upstream)
	if err != nil || u.Host == "" {
		return fmt.Errorf("upstream %q is not a URL", c.Upstream)
	}
	if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		// Plain http to a remote host puts the upstream key on the wire in clear.
		return fmt.Errorf("upstream must be https unless the host is loopback, got %q", c.Upstream)
	}

	if len(c.Models) == 0 {
		return fmt.Errorf("models allowlist is empty, which would deny everything")
	}
	if c.InjectionAction != "flag" && c.InjectionAction != "block" {
		return fmt.Errorf("injection_action must be \"flag\" or \"block\", got %q", c.InjectionAction)
	}
	if len(c.Keys) == 0 {
		return fmt.Errorf("no keys configured")
	}

	seenName := map[string]bool{}
	seenSecret := map[string]bool{}
	for i, k := range c.Keys {
		switch {
		case k.Name == "":
			return fmt.Errorf("keys[%d]: name is empty", i)
		case seenName[k.Name]:
			return fmt.Errorf("keys[%d]: duplicate name %q", i, k.Name)
		case len(k.Secret) < 16:
			// Short secrets are guessable and show up in audit logs by accident.
			return fmt.Errorf("keys[%d] %q: secret must be at least 16 characters", i, k.Name)
		case seenSecret[k.Secret]:
			return fmt.Errorf("keys[%d] %q: secret is reused", i, k.Name)
		case k.DailyTokens <= 0:
			return fmt.Errorf("keys[%d] %q: daily_tokens must be > 0", i, k.Name)
		case k.RPM <= 0:
			return fmt.Errorf("keys[%d] %q: requests_per_minute must be > 0", i, k.Name)
		}
		seenName[k.Name] = true
		seenSecret[k.Secret] = true

		for _, m := range k.Models {
			if !contains(c.Models, m) {
				return fmt.Errorf("keys[%d] %q: model %q is not in the global allowlist", i, k.Name, m)
			}
		}
	}
	return nil
}

func isLoopback(host string) bool {
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
