package model

import (
	"net/url"
	"regexp"
	"strings"
)

const redacted = "REDACTED"

var (
	urlPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	// credentialPattern matches a credential name followed by its value:
	// "Authorization: Bearer x", "api_key=x", "--token x".
	credentialPattern = regexp.MustCompile(`(?i)(-{0,2}[A-Za-z0-9_-]*(?:authorization|token|secret|passw|api[-_]?key|cookie|credential|private[-_]?key)[A-Za-z0-9_-]*)(\s*[:=]\s*|\s+)((?:bearer|basic)\s+)?([^\s"'&;,]+)`)
	schemePattern     = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
)

// Redact removes what may be a credential from a URL or a command before it is
// reported: user information and query values in URLs, the value after a
// credential name, and Bearer or Basic tokens. ${VAR} and $VAR references are
// kept, since they hold no value.
func Redact(s string) string {
	s = urlPattern.ReplaceAllStringFunc(s, redactURL)
	s = credentialPattern.ReplaceAllStringFunc(s, func(match string) string {
		m := credentialPattern.FindStringSubmatch(match)
		name, separator, scheme, value := m[1], m[2], m[3], m[4]
		// Whitespace separates a value only after a flag; elsewhere it is prose.
		if strings.TrimSpace(separator) == "" && !strings.HasPrefix(name, "-") {
			return match
		}
		if strings.HasPrefix(value, "$") || value == redacted {
			return match
		}
		return name + separator + scheme + redacted
	})
	return schemePattern.ReplaceAllString(s, "${1} "+redacted)
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		scheme, _, _ := strings.Cut(raw, "://")
		return scheme + "://" + redacted
	}
	if u.User != nil {
		u.User = url.User(redacted)
	}
	if u.RawQuery != "" {
		query := u.Query()
		for key := range query {
			query[key] = []string{redacted}
		}
		u.RawQuery = query.Encode()
	}
	return u.String()
}
