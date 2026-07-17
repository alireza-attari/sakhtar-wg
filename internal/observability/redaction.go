package observability

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

const redacted = "[REDACTED]"

var (
	credentialURL    = regexp.MustCompile(`(?i)(https?://)[^/@\s]+@`)
	secretAssignment = regexp.MustCompile(`(?i)\b(private_key|preshared_key|password|token|authorization|ssh_material)\s*[:=]\s*[^\s,}]+`)
	pemMaterial      = regexp.MustCompile(`(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----`)
)

func sensitiveKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, fragment := range []string{"private_key", "preshared", "password", "token", "authorization", "cookie", "ssh_material", "raw_header", "config_body", "sni", "host"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return key == "headers" || key == "header"
}

// RedactText removes credential-bearing URLs, common secret assignments, and
// PEM/SSH material from errors before they reach logs or status responses.
func RedactText(value string) string {
	value = credentialURL.ReplaceAllString(value, `${1}`+redacted+`@`)
	value = secretAssignment.ReplaceAllStringFunc(value, func(match string) string {
		if i := strings.IndexAny(match, ":="); i >= 0 {
			return match[:i+1] + redacted
		}
		return redacted
	})
	value = pemMaterial.ReplaceAllString(value, redacted)
	return value
}

type redactingHandler struct{ next slog.Handler }

func RedactingHandler(next slog.Handler) slog.Handler { return redactingHandler{next: next} }

func (h redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h redactingHandler) Handle(ctx context.Context, record slog.Record) error {
	copy := slog.NewRecord(record.Time, record.Level, RedactText(record.Message), record.PC)
	record.Attrs(func(attr slog.Attr) bool { copy.AddAttrs(redactAttr(attr)); return true })
	return h.next.Handle(ctx, copy)
}

func (h redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redactedAttrs := make([]slog.Attr, len(attrs))
	for i, attr := range attrs {
		redactedAttrs[i] = redactAttr(attr)
	}
	return redactingHandler{next: h.next.WithAttrs(redactedAttrs)}
}

func (h redactingHandler) WithGroup(name string) slog.Handler {
	return redactingHandler{next: h.next.WithGroup(name)}
}

func redactAttr(attr slog.Attr) slog.Attr {
	attr.Value = attr.Value.Resolve()
	if sensitiveKey(attr.Key) {
		return slog.String(attr.Key, redacted)
	}
	if attr.Value.Kind() == slog.KindGroup {
		children := attr.Value.Group()
		for i := range children {
			children[i] = redactAttr(children[i])
		}
		return slog.Attr{Key: attr.Key, Value: slog.GroupValue(children...)}
	}
	if attr.Value.Kind() == slog.KindString {
		attr.Value = slog.StringValue(RedactText(attr.Value.String()))
	}
	return attr
}

func NewJSONLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(RedactingHandler(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})))
}
