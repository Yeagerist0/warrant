// Package execute runs a plan's actions and turns each one into evidence the
// ledger will judge. It is the point where every other package pays off: the
// scope gate decides a request may go out, the egress client sends it and
// re-checks every redirect, recon and the planner decided it was worth trying,
// and here the response becomes typed claims that the evidence package either
// accepts or refuses.
//
// The design choice that matters: the executor does not decide whether a probe
// is a finding. It gathers what it honestly observed -- with a control and
// repeated reproductions, because a single hit is not evidence -- and hands a
// Finding to the ledger, which applies the policy. Most probes come back "not
// reportable", and that is the system working, not failing. An agent that turns
// every 200 into a bug is exactly the failure this project exists to prevent.
//
// Two hard rules. A NEEDS-CONFIRM action (a form submission, a state-changing
// verb) is never run unless the operator opted in; the default is to skip it
// and say so. And nothing is sent that the plan did not already mark safe and
// that egress will not re-authorize against scope at send time.
package execute

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/Yeagerist0/warrant/internal/egress"
	"github.com/Yeagerist0/warrant/internal/evidence"
	"github.com/Yeagerist0/warrant/internal/plan"
)

type Policy struct {
	// AllowUnsafe runs actions the plan marked NEEDS-CONFIRM. Off by default:
	// submitting a form or a state-changing verb needs a human's yes.
	AllowUnsafe bool
	// Replays is how many times a probe is repeated to satisfy the ledger's
	// "one hit is a coincidence" bar. Minimum 2.
	Replays int
}

func DefaultPolicy() Policy { return Policy{AllowUnsafe: false, Replays: 2} }

// Result is what happened for one action: either it was skipped (and why), it
// errored, or it ran and produced a Finding the ledger reviewed.
type Result struct {
	Action     plan.Action
	Skipped    bool
	SkipReason string
	Err        error

	Status  int
	Finding *evidence.Finding
	Verdict evidence.Verdict
	// Note carries a short human summary for probes that don't produce a
	// reviewable finding (method enumeration, an enforced-authz negative).
	Note string
}

type Executor struct {
	client *egress.Client
	policy Policy
}

func New(c *egress.Client, p Policy) *Executor {
	if p.Replays < 2 {
		p.Replays = 2
	}
	return &Executor{client: c, policy: p}
}

// Run executes every action it is allowed to, in the order given (the plan is
// already ranked), and returns one Result per action.
func (e *Executor) Run(ctx context.Context, actions []plan.Action) []Result {
	out := make([]Result, 0, len(actions))
	for _, a := range actions {
		out = append(out, e.runOne(ctx, a))
	}
	return out
}

func (e *Executor) runOne(ctx context.Context, a plan.Action) Result {
	r := Result{Action: a}
	if !a.Safe && !e.policy.AllowUnsafe {
		r.Skipped = true
		r.SkipReason = "action is NEEDS-CONFIRM (state-changing); operator confirmation required"
		return r
	}
	switch a.Kind {
	case plan.ParamTamper:
		return e.execParamTamper(ctx, a)
	case plan.MissingAuth:
		return e.execMissingAuth(ctx, a)
	case plan.MethodProbe:
		return e.execMethodProbe(ctx, a)
	case plan.SecurityHeaders:
		return e.execSecurityHeaders(ctx, a)
	default:
		r.Skipped = true
		r.SkipReason = "no executor for action kind " + string(a.Kind)
		return r
	}
}

// execParamTamper is the fullest example. It fetches the original object as a
// baseline (the control -- "does this endpoint just 200 for everything?"),
// then the tampered id, repeated. A tampered id that returns a distinct 2xx is
// a real primitive; but whether that adjacent object belongs to someone else is
// reachability the executor cannot establish alone, so it says so and lets the
// ledger cap the severity. A tampered id that gets 401/403/404 is authorization
// working, and is recorded as a refuted claim, not swept away.
func (e *Executor) execParamTamper(ctx context.Context, a plan.Action) Result {
	r := Result{Action: a}

	baseline, err := e.client.Do(ctx, a.Method, originalURL(a), nil)
	if err != nil {
		r.Err = err
		return r
	}
	var last *egress.Response
	sameEachTime := true
	for i := 0; i < e.policy.Replays; i++ {
		resp, err := e.client.Do(ctx, a.Method, a.URL, nil)
		if err != nil {
			r.Err = err
			return r
		}
		if last != nil && (last.Status != resp.Status || bodyDigest(last.Body) != bodyDigest(resp.Body)) {
			sameEachTime = false
		}
		last = resp
	}
	r.Status = last.Status

	authzEnforced := last.Status == 401 || last.Status == 403 || last.Status == 404
	distinct := is2xx(last.Status) && is2xx(baseline.Status) &&
		bodyDigest(last.Body) != bodyDigest(baseline.Body)

	f := &evidence.Finding{
		Title:   fmt.Sprintf("Object-level authorization on %s (param %s)", a.Method+" "+pathOf(a.URL), a.Param),
		Claimed: evidence.High,
	}
	switch {
	case authzEnforced:
		f.Claims = append(f.Claims, evidence.Claim{
			ID: "P1", Kind: evidence.Primitive, Status: evidence.Refuted, Supports: evidence.Medium,
			Text: fmt.Sprintf("tampered id (%s) returned %d; object-level authorization appears enforced", a.Mutation, last.Status),
		})
		r.Note = fmt.Sprintf("authz enforced: %s -> %d", a.Mutation, last.Status)
	case distinct && sameEachTime:
		f.Claims = append(f.Claims, evidence.Claim{
			ID: "P1", Kind: evidence.Primitive, Status: evidence.Observed, Supports: evidence.Medium,
			VictimScoped: true,
			Text:         fmt.Sprintf("adjacent id (%s) returns %d with content distinct from the original object", a.Mutation, last.Status),
			Exhibits: []evidence.Exhibit{{
				ID: "P1-x", Replays: e.policy.Replays,
				Request:  a.Method + " " + a.URL,
				Response: fmt.Sprintf("%d, %d bytes", last.Status, len(last.Body)),
				Control:  fmt.Sprintf("original object %s returned %d, %d bytes (so this is not '200 for everything')", originalURL(a), baseline.Status, len(baseline.Body)),
			}},
		})
		// Reachability is the missing half and the executor is honest that it
		// did not establish it. The ledger will block on this, correctly.
		f.Claims = append(f.Claims, evidence.Claim{
			ID: "R1", Kind: evidence.Reachability, Status: evidence.Untested, Supports: evidence.High,
			Text: "not established that the adjacent id belongs to another user; need a second account or an id-disclosure to prove cross-user access",
		})
	default:
		r.Note = fmt.Sprintf("no distinct object exposed (status %d); nothing to claim", last.Status)
		return r
	}
	r.Finding = f
	r.Verdict = f.Review(evidence.DefaultPolicy())
	return r
}

// execMissingAuth re-requests a sensitive-looking endpoint (the client sends no
// credentials). Answering unauthenticated is a primitive, but on its own it is
// the Exodus trap: without showing how an attacker addresses a victim's data,
// it is a design note. The executor records the primitive as victim-scoped with
// no reachability, so the ledger blocks it and prints exactly what to go prove.
func (e *Executor) execMissingAuth(ctx context.Context, a plan.Action) Result {
	r := Result{Action: a}
	var last *egress.Response
	allOK := true
	for i := 0; i < e.policy.Replays; i++ {
		resp, err := e.client.Do(ctx, a.Method, a.URL, nil)
		if err != nil {
			r.Err = err
			return r
		}
		if !is2xx(resp.Status) {
			allOK = false
		}
		last = resp
	}
	r.Status = last.Status
	if !allOK {
		r.Note = fmt.Sprintf("endpoint did not answer unauthenticated (status %d)", last.Status)
		return r
	}
	f := &evidence.Finding{
		Title:   "Unauthenticated access to " + pathOf(a.URL),
		Claimed: evidence.High,
		Claims: []evidence.Claim{{
			ID: "P1", Kind: evidence.Primitive, Status: evidence.Observed, Supports: evidence.Medium,
			VictimScoped: true,
			Text:         fmt.Sprintf("%s answered %d with no credentials", a.URL, last.Status),
			Exhibits: []evidence.Exhibit{{
				ID: "P1-x", Replays: e.policy.Replays,
				Request:  a.Method + " " + a.URL + " (no Authorization, no Cookie)",
				Response: fmt.Sprintf("%d, %d bytes", last.Status, len(last.Body)),
				// Honest: there is no clean negative control without an authed
				// session to compare against, so this is left empty and the
				// ledger's control requirement will (correctly) block it.
			}},
		}, {
			ID: "R1", Kind: evidence.Reachability, Status: evidence.Untested, Supports: evidence.High,
			Text: "not established that this exposes a specific victim's data vs. public content; find the identifier disclosure or the sensitive field",
		}},
	}
	r.Finding = f
	r.Verdict = f.Review(evidence.DefaultPolicy())
	return r
}

func (e *Executor) execMethodProbe(ctx context.Context, a plan.Action) Result {
	r := Result{Action: a}
	resp, err := e.client.Do(ctx, a.Method, a.URL, nil)
	if err != nil {
		r.Err = err
		return r
	}
	r.Status = resp.Status
	allow := resp.Header.Get("Allow")
	if allow == "" {
		allow = resp.Header.Get("Access-Control-Allow-Methods")
	}
	if allow == "" {
		r.Note = fmt.Sprintf("%s -> %d, no Allow header advertised", a.Method, resp.Status)
		return r
	}
	r.Note = fmt.Sprintf("allowed methods: %s", allow)
	if writeVerb(allow) {
		r.Note += "  (advertises a state-changing verb worth checking)"
	}
	return r
}

func (e *Executor) execSecurityHeaders(ctx context.Context, a plan.Action) Result {
	r := Result{Action: a}
	resp, err := e.client.Do(ctx, a.Method, a.URL, nil)
	if err != nil {
		r.Err = err
		return r
	}
	r.Status = resp.Status
	want := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"}
	var missing []string
	for _, h := range want {
		if resp.Header.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	if len(missing) == 0 {
		r.Note = "all checked security headers present"
		return r
	}
	r.Note = "missing security headers: " + strings.Join(missing, ", ")
	return r
}

// --- helpers ---

func bodyDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func is2xx(status int) bool { return status >= 200 && status < 300 }

// originalURL reconstructs the pre-mutation URL for a param-tamper action by
// dropping the mutated value back to the example the world model recorded. The
// planner encodes the tamper in a.URL and the original value in a.Mutation
// ("1001 -> 1000 ..."); we rebuild by parsing the "from" side.
func originalURL(a plan.Action) string {
	from := beforeArrow(a.Mutation)
	if from == "" {
		return a.URL
	}
	return replaceParam(a.URL, a.Param, from)
}

func beforeArrow(s string) string {
	if i := strings.Index(s, " -> "); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return ""
}

func pathOf(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rest := rawURL[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			p := rest[j:]
			if q := strings.IndexByte(p, '?'); q >= 0 {
				return p[:q]
			}
			return p
		}
	}
	return rawURL
}

func replaceParam(rawURL, name, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func writeVerb(allow string) bool {
	up := strings.ToUpper(allow)
	for _, v := range []string{"PUT", "DELETE", "PATCH", "POST"} {
		if strings.Contains(up, v) {
			return true
		}
	}
	return false
}
