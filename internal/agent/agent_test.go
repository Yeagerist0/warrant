package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Yeagerist0/warrant/internal/execute"
	"github.com/Yeagerist0/warrant/internal/plan"
	"github.com/Yeagerist0/warrant/internal/scope"
)

// vulnApp is a deliberately vulnerable target with a KNOWN bug list:
//   - /account and /admin/users answer unauthenticated (missing auth)
//   - both expose a distinct object per id (textbook IDOR shape)
//   - /search returns the same page for every input (a decoy: id-like nothing)
//
// The point of the measurement is not whether the agent notices these -- it
// does -- but whether the ledger refuses to *file* them without reachability.
func vulnApp() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<a href="/admin/users?id=42">admin</a>
			<a href="/account?account_id=1001">account</a>
			<a href="/search?q=x">search</a>
			<a href="https://evil.example.net/collect">offsite</a>
		</body></html>`)
	})
	mux.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		fmt.Fprintf(w, "USER %s: secret-token-%s", id, id) // distinct per id, no auth
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("account_id")
		fmt.Fprintf(w, "ACCOUNT %s balance %s000", id, id) // distinct per id, no auth
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "same results for everyone") // no distinct object
	})
	return httptest.NewServer(mux)
}

func scopeFor(t *testing.T, serverURL string) *scope.Scope {
	t.Helper()
	u, _ := url.Parse(serverURL)
	port, _ := strconv.Atoi(u.Port())
	return &scope.Scope{
		Engagement: "measurement", Authority: "baked-in vulnerable app", AllowPrivate: true,
		Allow: []scope.Rule{{Host: u.Hostname(), Ports: []int{port}}},
	}
}

// This is the measurement. Against a target whose bugs we planted, the agent
// probes the IDOR/unauth surface, produces findings, and the ledger refuses
// every one that lacks reachability. The number that matters:
// reportable == 0, i.e. zero false-positive reports, while it still *engaged*
// the real vulnerable endpoints (refused > 0, not "found nothing").
func TestPipelinePrecisionAgainstKnownBugs(t *testing.T) {
	srv := vulnApp()
	defer srv.Close()
	s := scopeFor(t, srv.URL)

	out, err := Run(context.Background(), s, srv.URL+"/", execute.DefaultPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	executed, skipped, reportable, refused := out.Summary()
	t.Logf("endpoints=%d forms=%d actions=%d | executed=%d skipped=%d reportable=%d refused=%d",
		out.Endpoints, out.Forms, len(out.Actions), executed, skipped, reportable, refused)

	// It must have engaged the planted vulnerabilities, not sat idle.
	tamper, missAuth := 0, 0
	for _, a := range out.Actions {
		switch a.Kind {
		case plan.ParamTamper:
			tamper++
		case plan.MissingAuth:
			missAuth++
		}
	}
	if tamper == 0 || missAuth == 0 {
		t.Fatalf("agent failed to plan against the known IDOR/unauth surface: tamper=%d missAuth=%d", tamper, missAuth)
	}

	// The whole thesis: zero false-positive reports. Every IDOR/unauth primitive
	// the agent found is refused because reachability was never established.
	if reportable != 0 {
		t.Errorf("precision failure: %d findings reported without proven reachability", reportable)
		for _, r := range out.Results {
			if r.Finding != nil && r.Verdict.Reportable {
				t.Errorf("  wrongly reportable: %s", r.Finding.Title)
			}
		}
	}
	// And it must actually have produced (then refused) findings -- proving it
	// engaged the surface rather than finding nothing.
	if refused == 0 {
		t.Errorf("expected the ledger to refuse real-but-unprovable findings; got none")
	}
}

// The agent must never touch a target the scope file did not authorize, even
// when the vulnerable app links to it.
func TestPipelineStaysInScope(t *testing.T) {
	var offsiteHit bool
	off := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { offsiteHit = true }))
	defer off.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="%s/x">offsite</a><a href="/admin/users?id=1">onsite</a>`, off.URL)
	})
	mux.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := scopeFor(t, srv.URL)
	if _, err := Run(context.Background(), s, srv.URL+"/", execute.DefaultPolicy(), nil); err != nil {
		t.Fatal(err)
	}
	if offsiteHit {
		t.Fatal("agent left scope and contacted the offsite server")
	}
}

// Under the default policy, a state-changing action is never executed. Here the
// vulnerable app exposes a POST form; the agent must plan it but skip running it.
func TestUnsafeFormIsPlannedButNotRun(t *testing.T) {
	var loginPosted bool
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<form action="/login" method="post"><input name="username"><input name="password"></form>`)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			loginPosted = true
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	s := scopeFor(t, srv.URL)

	out, err := Run(context.Background(), s, srv.URL+"/", execute.DefaultPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if loginPosted {
		t.Fatal("agent submitted a form under the default (safe-only) policy")
	}
	plannedForm, skippedForm := false, false
	for _, a := range out.Actions {
		if strings.HasPrefix(a.ID, "form:") {
			plannedForm = true
		}
	}
	for _, r := range out.Results {
		if strings.HasPrefix(r.Action.ID, "form:") && r.Skipped {
			skippedForm = true
		}
	}
	if !plannedForm {
		t.Error("the POST form should have been planned")
	}
	if !skippedForm {
		t.Error("the POST form should have been skipped, not run")
	}
}
