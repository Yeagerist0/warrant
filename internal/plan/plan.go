// Package plan turns the world model into a ranked list of things worth trying.
//
// It only proposes. Nothing here sends a request or changes anything; a plan is
// inert data that a human can read top to bottom and an executor (not yet
// built) will later run one action at a time under the scope gate. Keeping the
// planner separate from execution is the same discipline as the rest of the
// project: decide first, act second, and make the decision auditable before it
// can touch the target.
//
// The catalog is fixed and typed. Actions come from a known set of check kinds,
// not from free text, so whatever proposes them later -- these rules today, an
// LLM tomorrow -- the executor still only ever runs a probe it understands.
// That is what makes an LLM safe to add here later: it can rank and suggest,
// but it cannot invent an action outside the catalog.
//
// The rules lean on what has actually paid: unauthenticated reach into
// sensitive functions, and identifier tampering. Recon first, then probe the
// places the map says are worth probing -- not a blind spray.
package plan

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Yeagerist0/warrant/internal/model"
)

type Kind string

const (
	// ParamTamper mutates an identifier-like parameter to test object-level
	// authorization (IDOR). Read-only: it re-requests with a different id.
	ParamTamper Kind = "param-tamper"
	// MissingAuth re-requests a sensitive-looking endpoint with no credentials
	// and lets the executor compare -- the "unauth reach" class.
	MissingAuth Kind = "missing-auth"
	// MethodProbe asks which verbs an endpoint allows. OPTIONS/HEAD are safe;
	// a proposed state-changing verb is marked unsafe and needs confirmation.
	MethodProbe Kind = "method-probe"
	// SecurityHeaders inspects response headers for missing protections.
	SecurityHeaders Kind = "security-headers"
)

// Action is one proposed probe. It is concrete enough to execute directly --
// method + URL are ready to send -- and carries the reason it was proposed so a
// reviewer can accept or reject it without re-deriving the logic.
type Action struct {
	ID       string
	Kind     Kind
	Priority int // higher runs first

	Method string
	URL    string

	Param    string // the parameter involved, if any
	Mutation string // human-readable description of what was changed
	// Safe is true when the probe does not change server state. The executor
	// must require explicit confirmation for an action that is not Safe.
	Safe      bool
	Rationale string
}

// Plan reads the world model and returns proposed actions, highest priority
// first, de-duplicated by ID.
func Plan(w *model.World) []Action {
	var actions []Action
	seen := map[string]bool{}
	add := func(a Action) {
		if a.ID == "" || seen[a.ID] {
			return
		}
		seen[a.ID] = true
		actions = append(actions, a)
	}

	hostsProbedForHeaders := map[string]bool{}

	for _, e := range w.Endpoints() {
		answered := respondedOK(e)

		// One security-header check per host, on an endpoint that actually
		// answered -- no point checking headers on a 404.
		if answered && !hostsProbedForHeaders[e.Host] {
			hostsProbedForHeaders[e.Host] = true
			add(Action{
				ID:        "sec-headers:" + e.Host,
				Kind:      SecurityHeaders,
				Priority:  20,
				Method:    "GET",
				URL:       firstExample(e),
				Safe:      true,
				Rationale: "no host-level check of security response headers yet",
			})
		}

		// Identifier tampering on id-like params (IDOR). Only when the endpoint
		// answered -- tampering an id on a 404 endpoint proves nothing.
		if answered {
			for _, name := range sortedKeys(e.Params) {
				if !looksLikeID(name) {
					continue
				}
				val := e.Params[name]
				mutated, desc := mutateID(val)
				if mutated == "" {
					continue
				}
				u := withParam(firstExample(e), name, mutated)
				if u == "" {
					continue
				}
				add(Action{
					ID:        fmt.Sprintf("idor:%s:%s", e.Key(), name),
					Kind:      ParamTamper,
					Priority:  80,
					Method:    e.Method,
					URL:       u,
					Param:     name,
					Mutation:  desc,
					Safe:      e.Method == "GET" || e.Method == "HEAD",
					Rationale: fmt.Sprintf("param %q looks like an object identifier; test object-level authorization", name),
				})
			}
		}

		// Unauthenticated reach into sensitive-looking endpoints. This is the
		// highest-paying class, so it ranks first.
		if answered && sensitivePath(e.Path) {
			add(Action{
				ID:        "unauth:" + e.Key(),
				Kind:      MissingAuth,
				Priority:  90,
				Method:    e.Method,
				URL:       firstExample(e),
				Safe:      e.Method == "GET" || e.Method == "HEAD",
				Rationale: fmt.Sprintf("path %q looks sensitive; re-request with no credentials and compare", e.Path),
			})
		}

		// What other verbs does a GET endpoint allow? OPTIONS is safe and often
		// leaks the answer without touching state.
		if e.Method == "GET" {
			add(Action{
				ID:        "methods:" + e.Key(),
				Kind:      MethodProbe,
				Priority:  30,
				Method:    "OPTIONS",
				URL:       firstExample(e),
				Safe:      true,
				Rationale: "enumerate allowed methods; a writable verb on a read endpoint is worth knowing",
			})
		}
	}

	// Forms that post to an endpoint are state-crossing input points. A GET
	// form's fields are just query params (recon already captured those), so we
	// focus on non-GET forms and surface them as method/auth context.
	for _, f := range w.Forms() {
		if f.Method == "GET" {
			continue
		}
		hasSecret := false
		for _, in := range f.Inputs {
			if isSecretField(in) {
				hasSecret = true
			}
		}
		pri := 40
		rationale := fmt.Sprintf("form submits %s to %s (fields: %s)", f.Method, f.Action, strings.Join(f.Inputs, ", "))
		if hasSecret {
			pri = 50
			rationale = "authentication form; handle credentials via the operator, never auto-fill -- " + rationale
		}
		add(Action{
			ID:        "form:" + f.Key(),
			Kind:      MethodProbe,
			Priority:  pri,
			Method:    f.Method,
			URL:       f.Action,
			Safe:      false, // submitting a form changes state
			Rationale: rationale,
		})
	}

	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Priority != actions[j].Priority {
			return actions[i].Priority > actions[j].Priority
		}
		return actions[i].ID < actions[j].ID
	})
	return actions
}

// respondedOK reports whether the endpoint ever returned a 2xx or 3xx. A probe
// against something that only ever 404'd is usually noise.
func respondedOK(e model.Endpoint) bool {
	for code := range e.Statuses {
		if code >= 200 && code < 400 {
			return true
		}
	}
	return false
}

func firstExample(e model.Endpoint) string {
	if len(e.Examples) > 0 {
		return e.Examples[0]
	}
	return e.Scheme + "://" + e.Host + e.Path
}

var idNameRe = regexp.MustCompile(`(?i)(^|[_\-])(id|uid|uuid|guid|user|users|account|acct|order|invoice|doc|document|file|record|ref|number|no|key|pid|oid)($|[_\-])`)

// looksLikeID is deliberately a touch generous: a false positive costs one
// read-only probe, a false negative misses the whole finding class.
func looksLikeID(name string) bool {
	n := strings.ToLower(name)
	if n == "id" || n == "uid" || n == "uuid" || n == "guid" {
		return true
	}
	return idNameRe.MatchString(name)
}

// mutateID proposes a neighbouring value to test authorization. It only knows
// how to nudge integers here; a real engagement would add GUID and hashid
// strategies, but a numeric decrement covers the common case and never
// fabricates a value out of nothing.
func mutateID(val string) (mutated, desc string) {
	val = strings.TrimSpace(val)
	if val == "" {
		return "", ""
	}
	if n, err := strconv.Atoi(val); err == nil {
		if n > 1 {
			return strconv.Itoa(n - 1), fmt.Sprintf("%d -> %d (adjacent object)", n, n-1)
		}
		return strconv.Itoa(n + 1), fmt.Sprintf("%d -> %d (adjacent object)", n, n+1)
	}
	return "", "" // non-numeric ids aren't tampered blindly
}

func withParam(rawURL, name, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
}

var sensitiveRe = regexp.MustCompile(`(?i)(^|/)(admin|internal|private|account|accounts|user|users|profile|billing|invoice|orders?|api|settings|config|dashboard|manage|export|report)($|/)`)

func sensitivePath(path string) bool { return sensitiveRe.MatchString(path) }

func isSecretField(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "pass") || strings.Contains(n, "secret") ||
		strings.Contains(n, "token") || n == "otp" || strings.Contains(n, "pin")
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
