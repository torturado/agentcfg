package model

import (
	"net/url"
	"regexp"
	"strings"
)

const redacted = "REDACTED"

const credentialName = `[A-Za-z0-9_-]*(?:authorization|bearer|token|secret|passw|api[-_]?key|cookie|credential|private[-_]?key)[A-Za-z0-9_-]*`

var (
	urlPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://\S+`)
	// assignmentPattern is a credential name and its value in one argument:
	// "Authorization: Bearer x", "api_key=x", "--token=x".
	// A JSON form such as {"api_key":"x"} keeps its leading punctuation.
	assignmentPattern = regexp.MustCompile(`(?is)^([^A-Za-z0-9_-]*-{0,2}` + credentialName + `)(\s*[:=]\s*)(.*)$`)
	// flagPattern is a credential flag whose value is the next argument.
	flagPattern = regexp.MustCompile(`(?i)^--?` + credentialName + `$`)
)

// RedactURL removes the user information and query values of a URL.
func RedactURL(raw string) string {
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

// Redact removes what may be a credential from a command line before it is
// reported. The line is split into arguments as a POSIX shell would, and an
// argument is replaced when it holds a URL with user information or a query,
// a credential name with its value ("Authorization: Bearer x", "api_key=x"),
// or follows a credential flag ("--token x"); a quoted script is redacted the
// same way. ${VAR} and $VAR references are kept, since they hold no value.
func Redact(line string) string {
	args := splitArgs(line)
	var b strings.Builder
	last := 0
	for i, arg := range args {
		value := arg.value
		if m := assignmentPattern.FindStringSubmatch(value); m != nil {
			if m[3] != "" && !isReference(m[3]) {
				value = m[1] + m[2] + redacted
			}
		} else if i > 0 && args[i-1].credentialFlag() && !isReference(value) && !(arg.bare && strings.HasPrefix(value, "-")) {
			value = redacted
		} else if strings.ContainsAny(value, " \t\n") {
			// A quoted script, as in sh -c '...', holds its own arguments.
			value = Redact(value)
		}
		value = urlPattern.ReplaceAllStringFunc(value, RedactURL)
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

func isReference(value string) bool { return strings.HasPrefix(value, "$") }

type argument struct {
	value      string
	start, end int
	// bare is set when no part of the argument was quoted or escaped.
	bare bool
}

// credentialFlag reports whether the argument is a flag, or a name followed by
// an empty assignment such as the "api_key": of a JSON object, whose value is
// the next argument.
func (a argument) credentialFlag() bool {
	if flagPattern.MatchString(a.value) {
		return true
	}
	m := assignmentPattern.FindStringSubmatch(a.value)
	return m != nil && m[3] == ""
}

// splitArgs splits a line into arguments with POSIX shell quoting: single
// quotes keep everything, double quotes and a bare backslash escape.
func splitArgs(line string) []argument {
	var args []argument
	var current strings.Builder
	start, inArg, bare := 0, false, true
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
			case c == '\\' && i+1 < len(line) && strings.IndexByte("\"\\$`", line[i+1]) >= 0:
				i++
				current.WriteByte(line[i])
			default:
				current.WriteByte(c)
			}
			continue
		case c == ' ' || c == '\t' || c == '\n':
			if inArg {
				args = append(args, argument{current.String(), start, i, bare})
				current.Reset()
				inArg = false
			}
			continue
		}
		if !inArg {
			start, inArg, bare = i, true, true
		}
		switch {
		case c == '\'' || c == '"':
			quoteChar, bare = c, false
		case c == '\\' && i+1 < len(line):
			i++
			bare = false
			current.WriteByte(line[i])
		default:
			current.WriteByte(c)
		}
	}
	if inArg {
		args = append(args, argument{current.String(), start, len(line), bare})
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
