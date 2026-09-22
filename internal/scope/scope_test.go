package scope

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func testScope() *Scope {
	return &Scope{
		Engagement: "test",
		Authority:  "local lab",
		Allow: []Rule{
			{Host: "*.example.com"},
			{Host: "api.other.com", Paths: []string{"/v1/"}, Methods: []string{"GET"}},
		},
		Deny: []Rule{
			{Host: "admin.example.com", Note: "explicitly excluded"},
		},
	}
}

func TestWildcardDoesNotMatchApex(t *testing.T) {
	// Bug-bounty scopes read *.example.com as "subdomains"; the apex is often a
	// different app with a different owner. Getting this wrong tests a host
	// nobody authorized.
	s := testScope()
	if d := s.Check("GET", mustURL(t, "https://example.com/")); d.Allowed {
		t.Errorf("apex example.com should not match *.example.com, got %v", d)
	}
	if d := s.Check("GET", mustURL(t, "https://sub.example.com/")); !d.Allowed {
		t.Errorf("sub.example.com should match *.example.com, got %v", d)
	}
	if d := s.Check("GET", mustURL(t, "https://a.b.example.com/")); !d.Allowed {
		t.Errorf("deep subdomain should match, got %v", d)
	}
}

func TestWildcardSuffixIsNotSubstring(t *testing.T) {
	// The classic: "notexample.com" must not match "*.example.com".
	s := testScope()
	for _, h := range []string{
		"https://notexample.com/",
		"https://evil-example.com/",
		"https://example.com.attacker.net/",
	} {
		if d := s.Check("GET", mustURL(t, h)); d.Allowed {
			t.Errorf("%s must not be in scope, got %v", h, d)
		}
	}
}

func TestDenyBeatsAllow(t *testing.T) {
	s := testScope()
	d := s.Check("GET", mustURL(t, "https://admin.example.com/"))
	if d.Allowed {
		t.Fatalf("deny rule must win over the *.example.com allow, got %v", d)
	}
}

func TestDefaultDeny(t *testing.T) {
	s := testScope()
	if d := s.Check("GET", mustURL(t, "https://unrelated.net/")); d.Allowed {
		t.Errorf("unnamed host must be denied, got %v", d)
	}
}

func TestPathAndMethodNarrowing(t *testing.T) {
	s := testScope()
	cases := []struct {
		method, raw string
		want        bool
	}{
		{"GET", "https://api.other.com/v1/users", true},
		{"POST", "https://api.other.com/v1/users", false}, // method not allowed
		{"GET", "https://api.other.com/v2/users", false},  // path not allowed
		{"GET", "https://api.other.com/", false},
	}
	for _, c := range cases {
		if got := s.Check(c.method, mustURL(t, c.raw)).Allowed; got != c.want {
			t.Errorf("%s %s: allowed=%v want %v", c.method, c.raw, got, c.want)
		}
	}
}

func TestPrivateAddressesBlockedUnlessOptedIn(t *testing.T) {
	s := testScope()
	s.Allow = append(s.Allow, Rule{Host: "127.0.0.1"}, Rule{Host: "10.0.0.5"}, Rule{Host: "localhost"})
	for _, h := range []string{"http://127.0.0.1:3000/", "http://10.0.0.5/", "http://localhost:8080/"} {
		if d := s.Check("GET", mustURL(t, h)); d.Allowed {
			t.Errorf("%s allowed with allow_private off: %v", h, d)
		}
	}
	s.AllowPrivate = true
	for _, h := range []string{"http://127.0.0.1:3000/", "http://localhost:8080/"} {
		if d := s.Check("GET", mustURL(t, h)); !d.Allowed {
			t.Errorf("%s denied with allow_private on: %v", h, d)
		}
	}
}

func TestNonHTTPSchemesRejected(t *testing.T) {
	s := testScope()
	s.AllowPrivate = true
	s.Allow = append(s.Allow, Rule{Host: "sub.example.com"})
	for _, raw := range []string{
		"file:///etc/passwd",
		"gopher://sub.example.com/",
		"ftp://sub.example.com/",
	} {
		if d := s.Check("GET", mustURL(t, raw)); d.Allowed {
			t.Errorf("%s should be rejected on scheme, got %v", raw, d)
		}
	}
}

func TestPortDoesNotDefeatHostMatch(t *testing.T) {
	s := testScope()
	if d := s.Check("GET", mustURL(t, "https://sub.example.com:8443/x")); !d.Allowed {
		t.Errorf("explicit port should not change host matching, got %v", d)
	}
}

func TestCaseInsensitiveHost(t *testing.T) {
	s := testScope()
	if d := s.Check("get", mustURL(t, "https://SUB.Example.COM/")); !d.Allowed {
		t.Errorf("host and method matching must be case-insensitive, got %v", d)
	}
}

func TestLoadRejectsUnsafeScopeFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct{ name, body, why string }{
		{"noauth.json", `{"engagement":"x","allow":[{"host":"a.com"}]}`, "missing authority"},
		{"noname.json", `{"authority":"x","allow":[{"host":"a.com"}]}`, "missing engagement"},
		{"empty.json", `{"engagement":"x","authority":"y","allow":[]}`, "empty allow list"},
		{"star.json", `{"engagement":"x","authority":"y","allow":[{"host":"*"}]}`, "bare wildcard"},
		{"midstar.json", `{"engagement":"x","authority":"y","allow":[{"host":"api.*.com"}]}`, "non-leading wildcard"},
		{"typo.json", `{"engagement":"x","authority":"y","allowed":[{"host":"a.com"}]}`, "typo'd key would authorize nothing"},
	}
	for _, c := range cases {
		if _, err := Load(write(c.name, c.body)); err == nil {
			t.Errorf("%s: expected load to fail (%s)", c.name, c.why)
		}
	}

	good := write("good.json", `{"engagement":"x","authority":"lab","allow":[{"host":"*.example.com"}]}`)
	s, err := Load(good)
	if err != nil {
		t.Fatalf("valid scope failed to load: %v", err)
	}
	if s.Engagement != "x" {
		t.Errorf("engagement = %q", s.Engagement)
	}
}

func TestPortNarrowing(t *testing.T) {
	// Two services on one host is the normal shape of a local lab, and of
	// plenty of real targets. A rule that names a port must not authorize the
	// neighbour that happens to share an address.
	s := &Scope{
		Engagement: "lab", Authority: "local", AllowPrivate: true,
		Allow: []Rule{{Host: "127.0.0.1", Ports: []int{3000}}},
	}
	if d := s.Check("GET", mustURL(t, "http://127.0.0.1:3000/")); !d.Allowed {
		t.Errorf("named port should be allowed: %v", d)
	}
	if d := s.Check("GET", mustURL(t, "http://127.0.0.1:9000/")); d.Allowed {
		t.Errorf("unnamed port on the same host must be denied: %v", d)
	}
}

func TestPortDefaultsFromScheme(t *testing.T) {
	s := &Scope{
		Engagement: "x", Authority: "y",
		Allow: []Rule{{Host: "a.example.com", Ports: []int{443}}},
	}
	if d := s.Check("GET", mustURL(t, "https://a.example.com/")); !d.Allowed {
		t.Errorf("https with no explicit port should resolve to 443: %v", d)
	}
	if d := s.Check("GET", mustURL(t, "http://a.example.com/")); d.Allowed {
		t.Errorf("http defaults to 80, which is not in the rule: %v", d)
	}
}

func TestEmptyPortsMeansAnyPort(t *testing.T) {
	s := testScope()
	if d := s.Check("GET", mustURL(t, "https://sub.example.com:8443/")); !d.Allowed {
		t.Errorf("a rule with no ports should still match any port: %v", d)
	}
}
