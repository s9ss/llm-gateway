package guard

import (
	"regexp"
	"strings"
)

// This is a heuristic, not a classifier. It catches the lazy version of prompt
// injection: the kind people paste straight out of a blog post. Anything
// rewritten by someone who knows what they are doing walks right past it.
//
// Its actual job is to make injection attempts visible in the audit log, which
// is the only way you ever learn what is being tried against you.

type rule struct {
	weight int
	label  string
	re     *regexp.Regexp
}

var rules = []rule{
	{30, "instruction_override", regexp.MustCompile(
		`(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|preceding)\b[^.\n]{0,24}\b(instruction|prompt|direction|rule|context)s?\b`)},
	{25, "prompt_exfiltration", regexp.MustCompile(
		`(?i)\b(print|reveal|show|output|repeat|leak|dump)\b[^.\n]{0,32}\b(system prompt|initial prompt|your instructions|hidden instructions|pre-?prompt)\b`)},
	{20, "role_hijack", regexp.MustCompile(
		`(?i)(\byou are now\b|\bfrom now on you\b|\bact as (an? )?(unrestricted|jailbroken|dan|developer mode)\b|\bpretend (to be|you are)\b)`)},
	{20, "delimiter_spoof", regexp.MustCompile(
		`(?i)(<\|\s*im_start\s*\|>|<\|\s*im_end\s*\|>|###\s*system|\[/?INST\]|</?\s*system\s*>)`)},
	{15, "shell_payload", regexp.MustCompile(
		`(?i)(\bcurl\s+-|\bwget\s+http|\bnc\s+-e\b|\bbash\s+-i\b|\bsh\s+-c\b|\bpowershell(\.exe)?\s+-|\brm\s+-rf\s+/\b|\bbase64\s+-d\b)`)},
	{10, "encoding_evasion", regexp.MustCompile(
		`(?i)\b(base64|rot13|hex|url)[- ]?encod\w*\b[^.\n]{0,32}\b(payload|command|instruction|prompt|string)\b`)},
}

// Secrets that should never appear in a completion. Written as separate
// patterns because one big alternation is impossible to debug when a response
// comes back mangled.
var (
	rePrivateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	reSecret     = []*regexp.Regexp{
		regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`),
		regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`),
		regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`),
		regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}`),
	}
)

// Score returns a 0-100 number and the labels that fired.
func Score(text string) (int, []string) {
	if text == "" {
		return 0, nil
	}
	total := 0
	var hits []string
	for _, r := range rules {
		if r.re.MatchString(text) {
			total += r.weight
			hits = append(hits, r.label)
		}
	}
	if total > 100 {
		total = 100
	}
	return total, hits
}

// Redact replaces credential-shaped strings with a marker. Returns how many
// replacements were made so the audit log can show that something was caught.
func Redact(body []byte) ([]byte, int) {
	n := 0
	out := rePrivateKey.ReplaceAllFunc(body, func([]byte) []byte {
		n++
		return []byte("[redacted:private-key]")
	})
	for _, re := range reSecret {
		out = re.ReplaceAllFunc(out, func([]byte) []byte {
			n++
			return []byte("[redacted:credential]")
		})
	}
	return out, n
}

// Text flattens a decoded request body into one string for scoring. It walks
// the two shapes that matter: chat completions (messages[].content) and the
// responses API (input). Content can be a string or a list of parts.
func Text(payload map[string]any) string {
	var b strings.Builder
	collect(payload["messages"], &b)
	collect(payload["input"], &b)
	return b.String()
}

func collect(v any, b *strings.Builder) {
	switch t := v.(type) {
	case string:
		b.WriteString(t)
		b.WriteByte('\n')
	case []any:
		for _, item := range t {
			collect(item, b)
		}
	case map[string]any:
		for _, key := range []string{"content", "text", "input"} {
			if inner, ok := t[key]; ok {
				collect(inner, b)
			}
		}
	}
}
