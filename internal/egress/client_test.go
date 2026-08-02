package egress

import (
	"context"
	"net"
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
	// Two records for one request: Check's own ALLOW GET, and the dial-time
	// ALLOW DNS for the address it actually connected to -- safeDialContext's
	// half of the scope gate, which Check alone can't provide for a DNS name
	// (see internal/scope.ResolvedIPAllowed).
	if len(rec.got) != 2 || !strings.HasPrefix(rec.got[0], "ALLOW GET") || !strings.HasPrefix(rec.got[1], "ALLOW DNS") {
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
	// Three records: hop one's ALLOW GET, its dial-time ALLOW DNS (it was in
	// scope, so the dialer ran), then hop two's DENY GET -- refused by Check
	// before any dial was attempted, so no DNS record follows it.
	if len(rec.got) != 3 || !strings.HasPrefix(rec.got[1], "ALLOW DNS") || !strings.HasPrefix(rec.got[2], "DENY GET") {
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

// fakeResolver stands in for real DNS so a test can make a hostname resolve
// to whatever address the rebinding scenario needs, deterministically.
type fakeResolver struct {
	ips []net.IP
}

func (f fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	addrs := make([]net.IPAddr, len(f.ips))
	for i, ip := range f.ips {
		addrs[i] = net.IPAddr{IP: ip}
	}
	return addrs, nil
}

// This is the attack safeDialContext exists for: scope.Check only ever sees
// the hostname string in the URL, so an allow-listed DNS name that resolves
// to a private address -- the rebinding case, where the answer at connect
// time differs from whatever it was (or would have been) when scope was
// decided -- must still be refused, even though nothing about the URL itself
// looks private. Here "attacker.example.com" would pass Check fine; the
// resolver is rigged to answer with a loopback address, which is the part a
// real rebinding attacker controls.
func TestSafeDialContext_HostnameResolvingToPrivateIPIsRefused(t *testing.T) {
	s := &scope.Scope{Engagement: "test", Authority: "local lab"} // AllowPrivate defaults false
	rec := &recorder{}
	dial := safeDialContext(s, rec, fakeResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}})

	_, err := dial(context.Background(), "tcp", "attacker.example.com:80")
	if err == nil {
		t.Fatal("expected the dial to be refused")
	}
	if !strings.Contains(err.Error(), "private/loopback") {
		t.Errorf("error = %v, want it to name the private/loopback reason", err)
	}
	if len(rec.got) != 1 || !strings.HasPrefix(rec.got[0], "DENY DNS") {
		t.Errorf("audit trail = %v, want exactly one DENY DNS record", rec.got)
	}
}

// The counterpart: when the scope explicitly opts into private targets (a
// local lab, a deliberately internal engagement), the same resolved private
// address must be dialed, not refused -- proving the check is a real policy
// gate and not a hardcoded ban on RFC1918/loopback addresses.
func TestSafeDialContext_HostnameResolvingToPrivateIPIsAllowedWhenAllowPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("reached"))
	}))
	defer srv.Close()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	s := &scope.Scope{Engagement: "test", Authority: "local lab", AllowPrivate: true}
	rec := &recorder{}
	dial := safeDialContext(s, rec, fakeResolver{ips: []net.IP{net.ParseIP(host)}})

	conn, err := dial(context.Background(), "tcp", "internal.lab.invalid:"+port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	if len(rec.got) != 1 || !strings.HasPrefix(rec.got[0], "ALLOW DNS") {
		t.Errorf("audit trail = %v, want exactly one ALLOW DNS record", rec.got)
	}
}

func asOOS(err error, target **OutOfScopeError) bool {
	if e, ok := err.(*OutOfScopeError); ok {
		*target = e
		return true
	}
	return false
}
