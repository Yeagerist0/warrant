package egress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Yeagerist0/warrant/internal/scope"
)

type recorder struct {
	mu  sync.Mutex
	got []string
}

func (r *recorder) Record(method string, u *url.URL, d scope.Decision) {
	r.mu.Lock()
	defer r.mu.Unlock()
	verdict := "DENY"
	if d.Allowed {
		verdict = "ALLOW"
	}
	r.got = append(r.got, verdict+" "+method+" "+u.Host)
}

// scopeFor authorizes exactly the given server URLs, host AND port. Every
// httptest server shares 127.0.0.1, so a host-only rule would authorize all of
// them at once and quietly void the point of these tests.
func scopeFor(t *testing.T, serverURLs ...string) *scope.Scope {
	t.Helper()
	s := &scope.Scope{Engagement: "test", Authority: "local lab", AllowPrivate: true}
	for _, raw := range serverURLs {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			t.Fatalf("test server URL %q has no port", raw)
		}
		s.Allow = append(s.Allow, scope.Rule{Host: u.Hostname(), Ports: []int{port}})
	}
	return s
}

func TestInScopeRequestSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "warrant/") {
			t.Errorf("tool should identify itself, got UA %q", r.Header.Get("User-Agent"))
		}
		w.WriteHeader(200)
		w.Write([]byte("hello"))
	}))
	defer srv.Close()

	rec := &recorder{}
	c := New(scopeFor(t, srv.URL), rec)
	resp, err := c.Do(context.Background(), "GET", srv.URL+"/x", nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 200 || string(resp.Body) != "hello" {
		t.Errorf("resp = %d %q", resp.Status, resp.Body)
	}
	if len(rec.got) != 1 || !strings.HasPrefix(rec.got[0], "ALLOW") {
		t.Errorf("audit trail = %v", rec.got)
	}
}

func TestOutOfScopeRequestNeverLeaves(t *testing.T) {
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	defer srv.Close()

	rec := &recorder{}
	c := New(&scope.Scope{Engagement: "test", Authority: "local lab",
		Allow: []scope.Rule{{Host: "somewhere.else.invalid"}}}, rec)
	_, err := c.Do(context.Background(), "GET", srv.URL+"/x", nil)
	if err == nil {
		t.Fatal("expected refusal")
	}
	var oos *OutOfScopeError
	if !asOOS(err, &oos) {
		t.Fatalf("want OutOfScopeError, got %T: %v", err, err)
	}
	if oos.ViaRedirect {
		t.Error("first-hop refusal should not be marked as a redirect")
	}
	if reached {
		t.Error("the server was contacted despite being out of scope")
	}
	if len(rec.got) != 1 || !strings.HasPrefix(rec.got[0], "DENY") {
		t.Errorf("refusal must be audited, got %v", rec.got)
	}
}

// The case this package exists for: hop one is authorized, hop two is not.
func TestRedirectOutOfScopeIsRefused(t *testing.T) {
	thirdParty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("out-of-scope third party was contacted via redirect")
	}))
	defer thirdParty.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, thirdParty.URL+"/sso", http.StatusFound)
	}))
	defer target.Close()

	rec := &recorder{}
	c := New(scopeFor(t, target.URL), rec)
	_, err := c.Do(context.Background(), "GET", target.URL+"/login", nil)
	if err == nil {
		t.Fatal("expected the redirect to be refused")
	}
	var oos *OutOfScopeError
	if !asOOS(err, &oos) {
		t.Fatalf("want OutOfScopeError, got %T: %v", err, err)
	}
	if !oos.ViaRedirect {
		t.Error("refusal should be flagged as happening mid-chain")
	}
	if len(rec.got) != 2 || !strings.HasPrefix(rec.got[1], "DENY") {
		t.Errorf("both hops should be audited, got %v", rec.got)
	}
}

func TestRedirectWithinScopeIsFollowed(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			http.Redirect(w, r, "/b", http.StatusFound)
			return
		}
		w.Write([]byte("landed"))
	}))
	defer srv.Close()

	c := New(scopeFor(t, srv.URL), &recorder{})
	resp, err := c.Do(context.Background(), "GET", srv.URL+"/a", nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(resp.Body) != "landed" {
		t.Errorf("body = %q", resp.Body)
	}
	if len(resp.Hops) != 2 {
		t.Errorf("hops = %v, want both recorded for the report", resp.Hops)
	}
}

func TestRedirectLoopIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()

	c := New(scopeFor(t, srv.URL), &recorder{})
	c.MaxRedirects = 3
	if _, err := c.Do(context.Background(), "GET", srv.URL+"/loop", nil); err == nil {
		t.Fatal("expected the redirect limit to stop an in-scope loop")
	}
}

func asOOS(err error, target **OutOfScopeError) bool {
	if e, ok := err.(*OutOfScopeError); ok {
		*target = e
		return true
	}
	return false
}
