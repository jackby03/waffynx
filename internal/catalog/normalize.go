package catalog

import "strings"

// Normalize applies the same transformation to request data and to the catalog's
// patterns, so a signature written in plain text also matches its own encodings.
//
// The pipeline, in order:
//
//	percent-decoding   %3C -> <, %20 -> space, %2F -> /
//	HTML entities      &lt; -> <, &#x3C; -> <
//	JSON escapes       \u003c -> <
//	lowercasing        UNION -> union
//	squashing          removes whitespace and /**/ comments
//
// Squashing is what makes "union select" cover "union/**/select", "union+select",
// "union%20select" and "union\tselect". It is also why patterns are cheap: no
// regex runs per rule per request.
//
// Decoding is lenient: malformed sequences are left as they are, because a
// request is hostile input and a decoder that errors gives an attacker a way to
// skip matching entirely.
func Normalize(s string, decoded bool) string {
	if !decoded {
		return normalizePass(s, false)
	}

	if strings.ContainsRune(s, '%') {
		s = percentDecode(s)
	}
	if strings.ContainsRune(s, '&') {
		s = htmlUnescape(s)
	}
	if strings.Contains(s, `\u`) {
		s = jsonUnescape(s)
	}
	return normalizePass(s, true)
}

// normalizePass lowercases and, when squashing, drops whitespace and /**/ comments.
func normalizePass(s string, squash bool) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		c := s[i]

		if squash {
			// "+" is a space in form encoding and a plus in JSON. Squashing removes
			// whitespace anyway, so treating it as space is equivalent to removing it,
			// and it is what makes "union+select" match "union select".
			if isSpace(c) || c == '+' {
				continue
			}
			// SQL block comment: /* ... */ is dropped entirely.
			//
			// The MySQL variant /*!50000 ... */ is different: the server executes
			// its content, so only the /*!NNNNN marker is dropped and the payload
			// inside keeps being scanned. Dropping the whole block would hide
			// "union/*!50000select*/" from the matcher.
			if c == '/' && i+1 < len(s) && s[i+1] == '*' {
				if i+2 < len(s) && s[i+2] == '!' {
					j := i + 3
					for j < len(s) && s[j] >= '0' && s[j] <= '9' {
						j++
					}
					i = j - 1
					continue
				}
				if end := strings.Index(s[i+2:], "*/"); end >= 0 {
					i = i + 2 + end + 1 // the loop's i++ lands just past the comment
					continue
				}
			}
		}

		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// percentDecode resolves %XX sequences, leaving anything malformed untouched.
func percentDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexDigit(s[i+1])
			lo, ok2 := hexDigit(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// entity is one HTML entity worth resolving. A full table is unnecessary: these
// are the ones that appear in encoded XSS payloads.
var entity = []struct {
	name string
	char string
}{
	{"&lt;", "<"},
	{"&gt;", ">"},
	{"&quot;", `"`},
	{"&apos;", "'"},
	{"&#39;", "'"},
	{"&#x27;", "'"},
	{"&#x3c;", "<"},
	{"&#x3e;", ">"},
	{"&#60;", "<"},
	{"&#62;", ">"},
	{"&#40;", "("},
	{"&#41;", ")"},
	{"&amp;", "&"},
}

func htmlUnescape(s string) string {
	for _, e := range entity {
		s = strings.ReplaceAll(s, e.name, e.char)
	}
	return s
}

// jsonUnescape rewrites \uXXXX sequences into the characters they represent, so
// {"q":"\u003cscript\u003e"} matches the same signature as <script>.
func jsonUnescape(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+5 < len(s) && s[i+1] == 'u' {
			var v rune
			ok := true
			for j := 2; j < 6; j++ {
				d, valid := hexDigit(s[i+j])
				if !valid {
					ok = false
					break
				}
				v = v<<4 | rune(d)
			}
			if ok {
				b.WriteRune(v)
				i += 5
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// normalizeInto writes the decoded form of src into dst (which must have capacity
// for len(src)) and returns the filled prefix. It exists so the request path does
// not allocate a string per field: with a 64 KB body the string round-trip was
// half the cost of evaluation.
func normalizeInto(dst []byte, src []byte, decoded bool) []byte {
	if !decoded {
		return squashInto(dst[:0], src, false)
	}

	buf := src
	if containsByte(buf, '%') {
		buf = percentDecodeBytes(buf, dst)
	}
	dst = dst[:0]
	// HTML/JSON escapes are rare in bulk; resolve them only when present, and only
	// then pay for a string copy.
	if containsByte(buf, '&') || containsSeq(buf, `\u`) {
		return squashInto(dst, []byte(Normalize(string(buf), true)), true)
	}
	return squashInto(dst, buf, true)
}

func squashInto(dst []byte, s []byte, squash bool) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if squash {
			if isSpace(c) || c == '+' {
				continue
			}
			if c == '/' && i+1 < len(s) && s[i+1] == '*' {
				if i+2 < len(s) && s[i+2] == '!' {
					j := i + 3
					for j < len(s) && s[j] >= '0' && s[j] <= '9' {
						j++
					}
					i = j - 1
					continue
				}
				if end := indexSeq(s[i+2:], "*/"); end >= 0 {
					i = i + 2 + end + 1
					continue
				}
			}
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

func percentDecodeBytes(src, dst []byte) []byte {
	dst = dst[:0]
	for i := 0; i < len(src); i++ {
		if src[i] == '%' && i+2 < len(src) {
			hi, ok1 := hexDigit(src[i+1])
			lo, ok2 := hexDigit(src[i+2])
			if ok1 && ok2 {
				dst = append(dst, hi<<4|lo)
				i += 2
				continue
			}
		}
		dst = append(dst, src[i])
	}
	return dst
}

func containsByte(b []byte, c byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return true
		}
	}
	return false
}

func containsSeq(b []byte, seq string) bool {
	return indexSeq(b, seq) >= 0
}

func indexSeq(b []byte, seq string) int {
	if len(seq) == 0 {
		return 0
	}
	for i := 0; i+len(seq) <= len(b); i++ {
		match := true
		for j := 0; j < len(seq); j++ {
			if b[i+j] != seq[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
