package lumoauth

import "strings"

// Agent capability matching, exactly as the LumoAuth server does it.
//
// The server stores every capability in one form and matches it with two
// wildcards, so comparing capability strings with == gets both wrong:
// "tool:search_web" is stored as "tool.search_web", and "invoices.*" covers
// "invoices.read".
//
//   - Stored form: trimmed, ASCII letters lower-cased, ':' and '-' turned into
//     '.', runs of '.' collapsed, '.' trimmed from both ends.
//   - Wildcards: "*" covers every action. A name that ends in ".*" covers every
//     action under that prefix, at any depth, but not the prefix itself:
//     "invoices.*" covers "invoices.read", never "invoices". A '*' anywhere
//     else is an ordinary character.
//
// The cases in sdk-contract/vectors/agent-capabilities.json are checked against
// the server's own matcher, and capability_test.go checks these functions
// against the same cases.

// capabilityWildcard is the bare wildcard that covers every action.
const capabilityWildcard = "*"

// capabilityTrim is PHP's trim() default set: space, tab, LF, CR, NUL, vertical tab.
const capabilityTrim = " \t\n\r\x00\x0b"

// NormalizeCapability returns a capability in the form that the server stores
// it: "Invoices:Read" and "invoices-read" both become "invoices.read". Only
// ASCII letters are lower-cased, as on the server.
func NormalizeCapability(capability string) string {
	s := strings.Trim(capability, capabilityTrim)
	var b strings.Builder
	b.Grow(len(s))
	lastDot := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case c == ':' || c == '-':
			c = '.'
		}
		if c == '.' {
			if lastDot {
				continue
			}
			lastDot = true
		} else {
			lastDot = false
		}
		b.WriteByte(c)
	}
	return strings.Trim(b.String(), ".")
}

// CapabilityCovers reports whether one capability covers an action, in any
// spelling of either. CapabilityCovers("users:*", "USERS-DELETE") is true;
// CapabilityCovers("invoices.*", "invoices") is false.
func CapabilityCovers(capability, action string) bool {
	capability = NormalizeCapability(capability)
	action = NormalizeCapability(action)
	if capability == "" || action == "" {
		return false
	}
	if capability == capabilityWildcard || capability == action {
		return true
	}
	if strings.HasSuffix(capability, ".*") {
		return strings.HasPrefix(action, capability[:len(capability)-1])
	}
	return false
}

// AnyCapabilityCovers reports whether any capability in the list covers the action.
func AnyCapabilityCovers(capabilities []string, action string) bool {
	for _, capability := range capabilities {
		if CapabilityCovers(capability, action) {
			return true
		}
	}
	return false
}
