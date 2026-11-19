package lumoauth

import "strings"

// Agent capability matching, exactly as the LumoAuth server does it.
//
// A capability is one of the agent's OAuth scope values, in the form
// <resource>:<action> ("invoices:read", "web:search"). LumoAuth refuses
// the dot form ("invoices.read") when a capability is registered or a scope is
// requested for its API. The server compares capabilities in one canonical
// form with two wildcards, so comparing capability strings with == gets both
// wrong: a dotted permission slug such as "invoices.read" compares equal to
// "invoices:read", and "invoices:*" covers "invoices:read".
//
//   - Canonical form (used only to compare): trimmed, ASCII letters
//     lower-cased, '.' turned into ':', runs of ':' collapsed, ':' trimmed
//     from both ends. A '-' is part of a name ("pull-requests:comment"), not a
//     separator.
//   - Wildcards: "*" covers every action. A name that ends in ":*" covers every
//     action under that prefix, at any depth, but not the prefix itself:
//     "invoices:*" covers "invoices:read", never "invoices". A '*' anywhere
//     else is an ordinary character.
//
// The cases in sdk-contract/vectors/agent-capabilities.json are checked against
// the server's own matcher, and capability_test.go checks these functions
// against the same cases.

// capabilityWildcard is the bare wildcard that covers every action.
const capabilityWildcard = "*"

// capabilitySeparator separates the resource from the action, and further parts.
const capabilitySeparator = ':'

// capabilityTrim is PHP's trim() default set: space, tab, LF, CR, NUL, vertical tab.
const capabilityTrim = " \t\n\r\x00\x0b"

// NormalizeCapability returns a capability in the canonical form that the
// server compares: "Invoices.Read" and "invoices::read" both become
// "invoices:read", while "invoices-read" stays as it is. Only ASCII letters
// are lower-cased, as on the server.
func NormalizeCapability(capability string) string {
	s := strings.Trim(capability, capabilityTrim)
	var b strings.Builder
	b.Grow(len(s))
	lastSeparator := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case c == '.':
			c = capabilitySeparator
		}
		if c == capabilitySeparator {
			if lastSeparator {
				continue
			}
			lastSeparator = true
		} else {
			lastSeparator = false
		}
		b.WriteByte(c)
	}
	return strings.Trim(b.String(), string(capabilitySeparator))
}

// CapabilityCovers reports whether one capability covers an action, in any
// spelling of either. CapabilityCovers("users:*", "USERS.DELETE") is true;
// CapabilityCovers("invoices:*", "invoices") and
// CapabilityCovers("invoices:read", "invoices-read") are false.
func CapabilityCovers(capability, action string) bool {
	capability = NormalizeCapability(capability)
	action = NormalizeCapability(action)
	if capability == "" || action == "" {
		return false
	}
	if capability == capabilityWildcard || capability == action {
		return true
	}
	if strings.HasSuffix(capability, ":*") {
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
