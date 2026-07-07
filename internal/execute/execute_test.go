package execute

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/Yeagerist0/warrant/internal/egress"
	"github.com/Yeagerist0/warrant/internal/evidence"
	"github.com/Yeagerist0/warrant/internal/plan"
	"github.com/Yeagerist0/warrant/internal/scope"
)

func scopeFor(t *testing.T, serverURL string) *scope.Scope {
	t.Helper()
	u, _ := url.Parse(serverURL)
	port, _ := strconv.Atoi(u.Port())
	return &scope.Scope{
		Engagement: "exec-test", Authority: "local", AllowPrivate: true,
		Allow: []scope.Rule{{Host: u.Hostname(), Ports: []int{port}}},
	}
}

func execFor(t *testing.T, s *scope.Scope) *Executor {
	return New(egress.New(s, nil), DefaultPolicy())
}

// A NEEDS-CONFIRM action must never be sent under the default policy.
func TestUnsafeActionIsSkipped(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()

	s := scopeFor(t, srv.URL)
	res := execFor(t, s).Run(context.Background(), []plan.Action{{
		Kind: plan.MethodProbe, Method: "POST", URL: srv.URL + "/login", Safe: false,
	}})
	if hit {
		t.Fatal("unsafe action was executed under default policy")
	}
	if !res[0].Skipped {
		t.Errorf("expected skip, got %+v", res[0])
	}
}

// The star case: a tampered id that exposes a distinct object is a real
// primitive, but the ledger must BLOCK it because reachability (is it someone
// else's object?) was never established. This is the anti-overclaim thesis.
func TestParamTamperDistinctObjectIsBlockedOnReachability(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.WriteHeader(200)
		fmt.Fprintf(w, "record for id=%s, unique body %s", id, id) // distinct per id
	}))
	defer srv.Close()

	s := scopeFor(t, srv.URL)
	a := plan.Action{
		Kind: plan.ParamTamper, Method: "GET",
		URL:   srv.URL + "/users?id=41",
		Param: "id", Mutation: "42 -> 41 (adjacent object)", Safe: true,
	}
	res := execFor(t, s).Run(context.Background(), []plan.Action{a})[0]
	if res.Finding == nil {
		t.Fatal("expected a finding to be produced")
	}
	if res.Verdict.Reportable {
		t.Errorf("distinct object without reachability must NOT be reportable: %v", res.Verdict)
	}
	blockedOnReach := false
	for _, b := range res.Verdict.Blocking {
		if contains(b, "victim-scoped identifier") {
			blockedOnReach = true
		}
	}
	if !blockedOnReach {
		t.Errorf("expected the reachability gate to block it, got %v", res.Verdict.Blocking)
	}
}

// When authorization is enforced (tampered id -> 403), that is a refuted claim,
// recorded honestly, not a finding.
func TestParamTamperEnforcedAuthzIsRefuted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "41" {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "your own record")
	}))
	defer srv.Close()

	s := scopeFor(t, srv.URL)
	a := plan.Action{
		Kind: plan.ParamTamper, Method: "GET",
		URL: srv.URL + "/users?id=41", Param: "id", Mutation: "42 -> 41 (adjacent object)", Safe: true,
	}
	res := execFor(t, s).Run(context.Background(), []plan.Action{a})[0]
	if res.Finding == nil || res.Verdict.Reportable {
		t.Fatalf("enforced authz should not be reportable: %+v", res.Verdict)
	}
	if res.Finding.Claims[0].Status != evidence.Refuted {
		t.Errorf("expected a refuted primitive, got status %q", res.Finding.Claims[0].Status)
	}
}

// Identical bodies for every id means no distinct object was exposed -- nothing
// to claim, and the executor must not invent one.
func TestParamTamperNoDistinctObjectMakesNoClaim(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "same page for everyone")
	}))
	defer srv.Close()

	s := scopeFor(t, srv.URL)
	a := plan.Action{
		Kind: plan.ParamTamper, Method: "GET",
		URL: srv.URL + "/x?id=41", Param: "id", Mutation: "42 -> 41 (adjacent object)", Safe: true,
	}
	res := execFor(t, s).Run(context.Background(), []plan.Action{a})[0]
	if res.Finding != nil {
		t.Errorf("identical bodies should produce no finding, got %+v", res.Finding)
	}
}

func TestMissingAuthBlockedWithoutControlAndReachability(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "account page")
	}))
	defer srv.Close()

	s := scopeFor(t, srv.URL)
	a := plan.Action{Kind: plan.MissingAuth, Method: "GET", URL: srv.URL + "/account", Safe: true}
	res := execFor(t, s).Run(context.Background(), []plan.Action{a})[0]
	if res.Finding == nil {
		t.Fatal("expected a finding")
	}
	if res.Verdict.Reportable {
		t.Errorf("unauth-answering endpoint with no control/reachability must not be reportable: %v", res.Verdict)
	}
}

func TestMissingAuthEndpointThatDeniesMakesNoClaim(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()
	s := scopeFor(t, srv.URL)
	a := plan.Action{Kind: plan.MissingAuth, Method: "GET", URL: srv.URL + "/account", Safe: true}
	res := execFor(t, s).Run(context.Background(), []plan.Action{a})[0]
	if res.Finding != nil {
		t.Errorf("401 endpoint should yield no finding, got %+v", res.Finding)
	}
}

func TestMethodProbeReadsAllowHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "GET, POST, DELETE")
		w.WriteHeader(204)
	}))
	defer srv.Close()
	s := scopeFor(t, srv.URL)
	a := plan.Action{Kind: plan.MethodProbe, Method: "OPTIONS", URL: srv.URL + "/x", Safe: true}
	res := execFor(t, s).Run(context.Background(), []plan.Action{a})[0]
	if res.Note == "" || !contains(res.Note, "DELETE") {
		t.Errorf("expected allowed methods incl DELETE in note, got %q", res.Note)
	}
	if !contains(res.Note, "state-changing") {
		t.Errorf("a write verb should be flagged, got %q", res.Note)
	}
}

func TestSecurityHeadersReportsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff") // present
		w.WriteHeader(200)
	}))
	defer srv.Close()
	s := scopeFor(t, srv.URL)
	a := plan.Action{Kind: plan.SecurityHeaders, Method: "GET", URL: srv.URL + "/", Safe: true}
	res := execFor(t, s).Run(context.Background(), []plan.Action{a})[0]
	if !contains(res.Note, "Content-Security-Policy") {
		t.Errorf("expected CSP to be reported missing, got %q", res.Note)
	}
	if contains(res.Note, "X-Content-Type-Options") {
		t.Errorf("present header should not be listed missing, got %q", res.Note)
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
