package model

import (
	"net/url"
	"regexp"
	"strings"
)

const redacted = "REDACTED"

const credentialName = `[A-Za-z0-9_-]*(?:authorization|bearer|token|secret|passw|api[-_]?key|cookie|credential|private[-_]?key)[A-Za-z0-9_-]*`

var (
	// urlPattern stops at quotes, commas and brackets, so URLs inside a JSON
	// argument are matched one by one.
	urlPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>,{}\[\]]+`)
	// assignmentPattern is a credential name and its value anywhere in an
	// argument: "Authorization: Bearer x", "api_key=x", "--token=x" and the
	// properties of a JSON object.
	assignmentPattern = regexp.MustCompile(`(?i)(` + credentialName + `)(["']?\s*[:=]\s*)((?:bearer|basic)\s+)?("[^"]*"|'[^']*'|[^\s,;&}\]"']+)`)
	// pendingPattern is a credential name whose value is the next argument:
	// a flag such as --token, or a name ending in ":" or "=".
	pendingPattern = regexp.MustCompile(`(?i)(?:^--?` + credentialName + `|` + credentialName + `["']?\s*[:=])$`)
	scheme         = regexp.MustCompile(`(?i)^(?:bearer|basic)$`)
	braced         = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)
	bare           = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`)
)

// RedactURL removes the user information and query values of a URL. A value
// that does not parse as a URL is replaced whole.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return redacted
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

// Redact removes what may be a credential from a command line before it is
// reported. The line is split into arguments as a POSIX shell would, and in
// each argument the user information and query of URLs, the value after a
// credential name ("Authorization: Bearer x", "api_key=x", a JSON property)
// and the argument after a credential flag ("--token x") are replaced. A
// quoted script, as in sh -c '...', is redacted the same way. A variable
// reference holds no value and is kept.
func Redact(line string) string {
	var b strings.Builder
	last := 0
	// pending is set while the next argument is a credential's value.
	pending := false
	for _, arg := range splitArgs(line) {
		value := arg.value
		wasPending := pending
		pending = pendingPattern.MatchString(value)
		switch {
		case wasPending && scheme.MatchString(value):
			pending = true // the value follows "Bearer"
		case wasPending:
			if !arg.reference(value) {
				value = redacted
			}
		case strings.ContainsAny(value, " \t\n"):
			value = Redact(value)
		default:
			value = assignmentPattern.ReplaceAllStringFunc(value, func(match string) string {
				m := assignmentPattern.FindStringSubmatch(match)
				if arg.reference(strings.Trim(m[4], `"'`)) {
					return match
				}
				return m[1] + m[2] + m[3] + redacted
			})
			value = urlPattern.ReplaceAllStringFunc(value, RedactURL)
		}
		if value == arg.value {
			continue
		}
		b.WriteString(line[last:arg.start])
		b.WriteString(quote(value))
		last = arg.end
	}
	b.WriteString(line[last:])
	return b.String()
}

type argument struct {
	value      string
	start, end int
	// literal is set when part of the argument was single-quoted, so the
	// shell expands no variable in it.
	literal bool
}

// reference reports whether value is a variable reference rather than a
// value: ${NAME}, or $NAME where the shell would expand it.
func (a argument) reference(value string) bool {
	return braced.MatchString(value) || (!a.literal && bare.MatchString(value))
}

// splitArgs splits a line into arguments with POSIX shell quoting: single
// quotes keep everything, double quotes and a bare backslash escape.
func splitArgs(line string) []argument {
	var args []argument
	var current strings.Builder
	start, inArg, literal := 0, false, false
	var quoteChar byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quoteChar == '\'':
			if c == '\'' {
				quoteChar = 0
			} else {
				current.WriteByte(c)
			}
			continue
		case quoteChar == '"':
			switch {
			case c == '"':
				quoteChar = 0
			case c == '\\' && i+1 < len(line) && line[i+1] == '\n':
				i++ // line continuation
			case c == '\\' && i+1 < len(line) && strings.IndexByte("\"\\$`", line[i+1]) >= 0:
				i++
				current.WriteByte(line[i])
			default:
				current.WriteByte(c)
			}
			continue
		case c == '\\' && i+1 < len(line) && line[i+1] == '\n':
			i++ // line continuation
			continue
		case c == ' ' || c == '\t' || c == '\n':
			if inArg {
				args = append(args, argument{current.String(), start, i, literal})
				current.Reset()
				inArg = false
			}
			continue
		}
		if !inArg {
			start, inArg, literal = i, true, false
		}
		switch {
		case c == '\'':
			quoteChar, literal = c, true
		case c == '"':
			quoteChar = c
		case c == '\\' && i+1 < len(line):
			i++
			current.WriteByte(line[i])
		default:
			current.WriteByte(c)
		}
	}
	if inArg {
		args = append(args, argument{current.String(), start, len(line), literal})
	}
	return args
}

// quote writes an argument back so a shell would read it as one.
func quote(value string) string {
	if strings.ContainsAny(value, " \t\n'\"\\$`&;|<>()") {
		return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
	}
	return value
}
