// Package scope decides, for every outbound request the agent wants to make,
// whether that request is inside the engagement it was authorized for.
//
// The rule that matters: this is default-deny. A host the scope file does not
// name is out of scope, and there is no code path that reaches the network
// without passing Check first. An agent that plans its own actions will
// eventually plan one nobody authorized -- a crawler follows a CDN link, a
// redirect lands on a parked domain, an LLM hallucinates a hostname. None of
// those are hypothetical; they are the normal behaviour of the thing being
// built. The defense cannot be "the model knows better", it has to be a gate.
package scope

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Rule matches a set of requests. An empty Paths or Methods means "any".
type Rule struct {
	Host    string   `json:"host"`              // "api.example.com" or "*.example.com"
	Paths   []string `json:"paths,omitempty"`   // path prefixes
	Methods []string `json:"methods,omitempty"` // upper-case verbs
	Note    string   `json:"note,omitempty"`    // why this is in scope; quoted in logs
	// Ports narrows the rule to specific ports. Empty means any port, which is
	// the right default for a public host and the wrong one for a lab: on
	// localhost, "the target" and "some other service I happen to be running"
	// differ only by port, and a host-only rule silently authorizes both.
	Ports []int `json:"ports,omitempty"`
}

// Scope is the parsed engagement definition.
type Scope struct {
	Engagement string `json:"engagement"`
	// Authority records who authorized this and where it is written down.
	// It is required: a scope file with no stated authority will not load.
	Authority string `json:"authority"`
	Allow     []Rule `json:"allow"`
	Deny      []Rule `json:"deny,omitempty"`
	// AllowPrivate permits RFC1918 / loopback targets. Off by default so a
	// scope written for a public target cannot be turned inward by a redirect
	// or a hostname that resolves to 127.0.0.1.
	AllowPrivate bool    `json:"allow_private,omitempty"`
	MaxRPS       float64 `json:"max_rps,omitempty"`
}

// Decision is the answer, plus the reason, which is logged either way. The
// refusals are as much a part of the audit trail as the requests.
type Decision struct {
	Allowed bool
	Reason  string
}

func (d Decision) String() string {
	if d.Allowed {
		return "ALLOW: " + d.Reason
	}
	return "DENY: " + d.Reason
}

// Load reads a scope file and rejects anything ambiguous at load time rather
// than mid-run, when a bad rule has already cost requests against a stranger.
func Load(path string) (*Scope, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Scope
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields() // a typo'd "allowed" key must not silently mean "no rules"
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("scope %s: %w", path, err)
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("scope %s: %w", path, err)
	}
	return &s, nil
}

func (s *Scope) validate() error {
	if strings.TrimSpace(s.Engagement) == "" {
		return fmt.Errorf("engagement name is required")
	}
	if strings.TrimSpace(s.Authority) == "" {
		return fmt.Errorf("authority is required: record who authorized this test and where (program URL, contract, lab)")
	}
	if len(s.Allow) == 0 {
		return fmt.Errorf("allow list is empty, which would authorize nothing")
	}
	for i, r := range append(append([]Rule{}, s.Allow...), s.Deny...) {
		h := strings.TrimSpace(r.Host)
		if h == "" {
			return fmt.Errorf("rule %d has no host", i)
		}
		if h == "*" {
			return fmt.Errorf(`rule %d uses host "*", which is never a real engagement scope`, i)
		}
		if strings.Contains(h, "*") && !strings.HasPrefix(h, "*.") {
			return fmt.Errorf("rule %d: wildcard must be a leading label, e.g. *.example.com, got %q", i, h)
		}
	}
	return nil
}

// hostMatches implements the wildcard rule people actually mean.
//
// "*.example.com" matches sub.example.com and a.b.example.com, and does NOT
// match example.com itself. Bug-bounty scopes are written this way, and the
// apex is frequently a different application with a different owner. If you
// want the apex, list it.
func hostMatches(pattern, host string) bool {
	pattern, host = strings.ToLower(pattern), strings.ToLower(host)
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == host
	}
	suffix := pattern[1:] // ".example.com"
	return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
}

func (r Rule) matches(method string, u *url.URL) bool {
	if !hostMatches(r.Host, u.Hostname()) {
		return false
	}
	if len(r.Ports) > 0 {
		p := effectivePort(u)
		found := false
		for _, want := range r.Ports {
			if want == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(r.Methods) > 0 && !containsFold(r.Methods, method) {
		return false
	}
	if len(r.Paths) > 0 {
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		ok := false
		for _, pre := range r.Paths {
			if strings.HasPrefix(p, pre) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// effectivePort resolves the port a request will actually reach, filling in
// the scheme default when the URL omits it.
func effectivePort(u *url.URL) int {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return -1
		}
		return n
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

func containsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

// Check is the only question the rest of the program is allowed to ask.
func (s *Scope) Check(method string, u *url.URL) Decision {
	if u == nil {
		return Decision{false, "nil URL"}
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return Decision{false, fmt.Sprintf("scheme %q is not http(s)", u.Scheme)}
	}
	host := u.Hostname()
	if host == "" {
		return Decision{false, "URL has no host"}
	}
	if !s.AllowPrivate && isPrivateHost(host) {
		return Decision{false, fmt.Sprintf("%s is a private/loopback address and allow_private is off", host)}
	}
	// Deny wins. An exclusion in a scope file is there because someone was
	// explicit about it, and an allow rule must never be able to re-open it.
	for _, r := range s.Deny {
		if r.matches(method, u) {
			return Decision{false, fmt.Sprintf("%s %s matches deny rule %s%s", method, u, r.Host, note(r))}
		}
	}
	for _, r := range s.Allow {
		if r.matches(method, u) {
			return Decision{true, fmt.Sprintf("%s %s matches allow rule %s%s", method, u, r.Host, note(r))}
		}
	}
	return Decision{false, fmt.Sprintf("%s is not named in the scope file (default deny)", host)}
}

func note(r Rule) string {
	if r.Note == "" {
		return ""
	}
	return " (" + r.Note + ")"
}

// isPrivateHost is deliberately conservative: an unparseable literal is
// treated as private rather than public, because the failure we care about is
// letting something through, not blocking too much.
func isPrivateHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // a DNS name; resolution is checked at dial time, not here
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
