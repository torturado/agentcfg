package model

import (
	"net/url"
	"regexp"
	"strings"
)

const redacted = "REDACTED"

const (
	credentialName  = `[A-Za-z0-9_-]*(?:authorization|token|secret|passw|api[-_]?key|cookie|credential|private[-_]?key)[A-Za-z0-9_-]*`
	credentialValue = `((?:bearer|basic)\s+)?("[^"]*"|'[^']*'|[^\s"'&;,]+)`
)

var (
	urlPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	// assignmentPattern matches "Authorization: Bearer x", "api_key=x" and
	// the JSON form "api_key": "x".
	assignmentPattern = regexp.MustCompile(`(?i)(` + credentialName + `)(["']?\s*[:=]\s*)` + credentialValue)
	// flagPattern matches "--token x" and "-password 'x'".
	flagPattern = regexp.MustCompile(`(?i)((?:^|\s)--?` + credentialName + `)(\s+)` + credentialValue)
)

// Redact removes what may be a credential from a URL or a command before it is
// reported: user information and query values in URLs, and the value after a
// credential name, as an assignment or a flag. ${VAR} and $VAR references are
// kept, since they hold no value.
func Redact(s string) string {
	s = urlPattern.ReplaceAllStringFunc(s, redactURL)
	for _, pattern := range []*regexp.Regexp{assignmentPattern, flagPattern} {
		s = pattern.ReplaceAllStringFunc(s, func(match string) string {
			m := pattern.FindStringSubmatch(match)
			name, separator, scheme, value := m[1], m[2], m[3], strings.Trim(m[4], `"'`)
			if strings.HasPrefix(value, "$") || strings.HasPrefix(value, "-") || value == redacted {
				return match
			}
			return name + separator + scheme + redacted
		})
	}
	return s
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
