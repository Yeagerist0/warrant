package recon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Yeagerist0/warrant/internal/egress"
	"github.com/Yeagerist0/warrant/internal/model"
	"github.com/Yeagerist0/warrant/internal/scope"
)

// scopeForServer authorizes exactly one test server's host+port.
func scopeForServer(t *testing.T, serverURL string) *scope.Scope {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	return &scope.Scope{
		Engagement:   "recon-test",
		Authority:    "local test server",
		AllowPrivate: true,
		Allow:        []scope.Rule{{Host: u.Hostname(), Ports: []int{port}}},
	}
}

func newCrawler(t *testing.T, s *scope.Scope, w *model.World) *Crawler {
	c := New(s, egress.New(s, nil), w)
	return c
}

func TestCrawlDiscoversLinksAndForms(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<a href="/about">About</a>
			<a href="/users?id=1">User</a>
			<form action="/login" method="post">
				<input name="username"><input name="password" type="password">
			</form>
		</body></html>`)
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/">home</a></body></html>`)
	})
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":1}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := scopeForServer(t, srv.URL)
	w := model.New()
	if err := newCrawler(t, s, w).Crawl(context.Background(), []string{srv.URL + "/"}); err != nil {
		t.Fatal(err)
	}

	eps := w.Endpoints()
	paths := map[string]bool{}
	for _, e := range eps {
		paths[e.Path] = true
	}
	for _, want := range []string{"/", "/about", "/users"} {
		if !paths[want] {
			t.Errorf("expected endpoint %s to be discovered; got %v", want, paths)
		}
	}
	// /users must have recorded the id parameter.
	for _, e := range eps {
		if e.Path == "/users" {
			if _, ok := e.Params["id"]; !ok {
				t.Errorf("/users should record param id, got %v", e.Params)
			}
		}
	}
	forms := w.Forms()
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	f := forms[0]
	if f.Method != "POST" || !strings.HasSuffix(f.Action, "/login") {
		t.Errorf("form action/method wrong: %+v", f)
	}
	if len(f.Inputs) != 2 {
		t.Errorf("form should have 2 inputs (username,password), got %v", f.Inputs)
	}
}

// The property the package exists to guarantee: an out-of-scope link is never
// fetched, even when the target links to it.
func TestCrawlNeverLeavesScope(t *testing.T) {
	var thirdPartyHit bool
	third := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		thirdPartyHit = true
	}))
	defer third.Close()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="%s/secret">offsite</a><a href="/ok">onsite</a>`, third.URL)
	}))
	defer srv.Close()

	s := scopeForServer(t, srv.URL)
	w := model.New()
	if err := newCrawler(t, s, w).Crawl(context.Background(), []string{srv.URL + "/"}); err != nil {
		t.Fatal(err)
	}
	if thirdPartyHit {
		t.Fatal("crawler fetched an out-of-scope third-party link")
	}
	// The onsite link must still have been crawled, so we know the crawl ran
	// and the scope gate is what stopped the third party -- not an early exit.
	// (Both httptest servers share 127.0.0.1 and differ only by port, so we
	// assert on behaviour, thirdPartyHit, rather than on recorded hostnames.)
	paths := map[string]bool{}
	for _, e := range w.Endpoints() {
		paths[e.Path] = true
	}
	if !paths["/ok"] {
		t.Errorf("onsite link /ok should have been crawled: %v", paths)
	}
}

func TestCrawlRespectsPageLimit(t *testing.T) {
	// Every page links to two fresh pages, so an unbounded crawl would explode.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="/%s0">a</a><a href="/%s1">b</a>`, r.URL.Path[1:], r.URL.Path[1:])
	}))
	defer srv.Close()

	s := scopeForServer(t, srv.URL)
	w := model.New()
	c := newCrawler(t, s, w)
	c.MaxPages = 5
	c.MaxDepth = 100
	if err := c.Crawl(context.Background(), []string{srv.URL + "/seed"}); err != nil {
		t.Fatal(err)
	}
	_, _, visited := w.Counts()
	if visited > 5 {
		t.Errorf("page limit not honored: visited %d, limit 5", visited)
	}
}

func TestCrawlRespectsDepthLimit(t *testing.T) {
	// /a -> /b -> /c -> /d ; depth 1 from /a should reach /b but not /c.
	next := map[string]string{"/a": "/b", "/b": "/c", "/c": "/d"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if n, ok := next[r.URL.Path]; ok {
			fmt.Fprintf(w, `<a href="%s">next</a>`, n)
		}
	}))
	defer srv.Close()

	s := scopeForServer(t, srv.URL)
	w := model.New()
	c := newCrawler(t, s, w)
	c.MaxDepth = 1
	c.MaxPages = 100
	if err := c.Crawl(context.Background(), []string{srv.URL + "/a"}); err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, e := range w.Endpoints() {
		paths[e.Path] = true
	}
	if !paths["/a"] || !paths["/b"] {
		t.Errorf("depth 1 should reach /a and /b: %v", paths)
	}
	if paths["/c"] {
		t.Errorf("depth 1 should NOT reach /c: %v", paths)
	}
}
