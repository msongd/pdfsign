package sign

import (
	"strings"
	"testing"
)

// TestPDFStringEscaping checks that PDF string-literal metacharacters can't
// break out of the (...) literal, on both the ASCII and the UTF-16BE paths.
func TestPDFStringEscaping(t *testing.T) {
	// ASCII path: ( ) \ are escaped.
	if got := pdfString(`a)b(c\d`); got != `(a\)b\(c\\d)` {
		t.Errorf("ASCII escaping: got %q", got)
	}

	// UTF-16BE path: a non-ASCII rune forces UTF-16, and U+2928 encodes to
	// bytes 0x29 0x28 — a ')' then '(' that must be escaped, not emitted raw.
	got := pdfString("x⤨y")
	inner := got[1 : len(got)-1] // strip the outer ( )
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(', ')':
			// Every literal paren byte must be preceded by a backslash.
			if i == 0 || inner[i-1] != '\\' {
				t.Fatalf("unescaped %q byte at %d in UTF-16 output %q", inner[i], i, got)
			}
		}
	}
	if !strings.HasPrefix(got, "(") || !strings.HasSuffix(got, ")") {
		t.Errorf("UTF-16 output not wrapped in a literal: %q", got)
	}
}
