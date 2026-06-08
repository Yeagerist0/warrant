package model

import (
	"net/url"
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

func TestSameEndpointDifferentQueryCollapses(t *testing.T) {
	// The reason this package exists: /users?id=1 and /users?id=2 are one
	// endpoint with a varying parameter, not two findings.
	w := New()
	w.Observe("GET", mustURL(t, "https://api.example.com/users?id=1"), 200)
	w.Observe("GET", mustURL(t, "https://api.example.com/users?id=2"), 200)

	eps := w.Endpoints()
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d: %+v", len(eps), eps)
	}
	e := eps[0]
	if e.Hits != 2 {
		t.Errorf("hits = %d, want 2", e.Hits)
	}
	if _, ok := e.Params["id"]; !ok {
		t.Errorf("param 'id' not recorded: %+v", e.Params)
	}
	if e.Statuses[200] != 2 {
		t.Errorf("status 200 count = %d, want 2", e.Statuses[200])
	}
}

func TestMethodAndPathSeparateEndpoints(t *testing.T) {
	w := New()
	w.Observe("GET", mustURL(t, "https://x.com/a"), 200)
	w.Observe("POST", mustURL(t, "https://x.com/a"), 201)
	w.Observe("GET", mustURL(t, "https://x.com/b"), 404)
	if got := len(w.Endpoints()); got != 3 {
		t.Fatalf("expected 3 distinct endpoints, got %d", got)
	}
}

func TestParamNamesAccumulateAcrossHits(t *testing.T) {
	w := New()
	w.Observe("GET", mustURL(t, "https://x.com/s?q=hi"), 200)
	w.Observe("GET", mustURL(t, "https://x.com/s?page=2"), 200)
	e := w.Endpoints()[0]
	if _, ok := e.Params["q"]; !ok {
		t.Error("param q missing")
	}
	if _, ok := e.Params["page"]; !ok {
		t.Error("param page missing")
	}
}

func TestExamplesAreCappedAndDeduped(t *testing.T) {
	w := New()
	for i := 0; i < 10; i++ {
		w.Observe("GET", mustURL(t, "https://x.com/s?q=1"), 200) // identical
	}
	e := w.Endpoints()[0]
	if len(e.Examples) != 1 {
		t.Errorf("identical URL should yield 1 example, got %d", len(e.Examples))
	}
}

func TestMarkVisitedIsOncePerURL(t *testing.T) {
	w := New()
	if !w.MarkVisited("https://x.com/a") {
		t.Error("first visit should return true")
	}
	if w.MarkVisited("https://x.com/a") {
		t.Error("second visit of same URL should return false")
	}
	if !w.MarkVisited("https://x.com/b") {
		t.Error("different URL should return true")
	}
}

func TestFormDedupAndInputSort(t *testing.T) {
	w := New()
	w.RecordForm(Form{Page: "https://x.com/", Action: "https://x.com/login", Method: "post", Inputs: []string{"password", "user", "user"}})
	w.RecordForm(Form{Page: "https://x.com/", Action: "https://x.com/login", Method: "POST", Inputs: []string{"user", "password"}})
	forms := w.Forms()
	if len(forms) != 1 {
		t.Fatalf("identical forms should dedup to 1, got %d", len(forms))
	}
	f := forms[0]
	if f.Method != "POST" {
		t.Errorf("method = %q, want POST", f.Method)
	}
	if len(f.Inputs) != 2 || f.Inputs[0] != "password" || f.Inputs[1] != "user" {
		t.Errorf("inputs not deduped/sorted: %v", f.Inputs)
	}
}

func TestFormMethodDefaultsToGet(t *testing.T) {
	w := New()
	w.RecordForm(Form{Action: "https://x.com/search", Method: "", Inputs: []string{"q"}})
	if w.Forms()[0].Method != "GET" {
		t.Errorf("empty form method should default to GET, got %q", w.Forms()[0].Method)
	}
}

func TestPathNormalization(t *testing.T) {
	w := New()
	w.Observe("GET", mustURL(t, "https://x.com"), 200) // no path
	if w.Endpoints()[0].Path != "/" {
		t.Errorf("empty path should normalize to /, got %q", w.Endpoints()[0].Path)
	}
}

func TestConcurrentObserveIsSafe(t *testing.T) {
	w := New()
	done := make(chan bool)
	for i := 0; i < 20; i++ {
		go func() {
			w.Observe("GET", mustURL(t, "https://x.com/a?n=1"), 200)
			w.RecordForm(Form{Action: "https://x.com/f", Inputs: []string{"a"}})
			w.MarkVisited("https://x.com/a")
			done <- true
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
	if len(w.Endpoints()) != 1 || len(w.Forms()) != 1 {
		t.Errorf("concurrent writes produced inconsistent state: %d eps, %d forms",
			len(w.Endpoints()), len(w.Forms()))
	}
}
