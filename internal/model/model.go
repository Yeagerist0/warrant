// Package model is what the agent knows about the target so far.
//
// Recon writes to it, the planner (not yet built) reads from it. Keeping the
// two apart behind a typed store matters: the planner should reason over a
// clean map of endpoints and forms, not re-parse raw HTML, and every fact in
// here should be traceable to a request that was actually made. Nothing in this
// package touches the network -- it only records what the scoped egress layer
// already fetched.
//
// The unit is the Endpoint, keyed by method + scheme + host + path. Two hits on
// /users?id=1 and /users?id=2 are the same endpoint with a parameter that
// varies; collapsing them is the whole point, because a planner wants "there is
// a /users endpoint that takes id", not two rows it has to re-derive.
package model

import (
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Endpoint is one addressable operation the agent has observed.
type Endpoint struct {
	Method string // upper-case verb
	Scheme string
	Host   string
	Path   string

	// Params is the set of query-parameter names seen across all hits, with an
	// example value for each (the last one observed). Names, not values, are
	// what a planner reasons about; the example is a convenience for a PoC.
	Params map[string]string
	// Examples holds a few full URLs that hit this endpoint, for evidence.
	Examples []string
	// Statuses counts the response codes this endpoint returned, so the planner
	// can tell "exists and answers" from "404 for everyone".
	Statuses map[int]int
	// Hits is the total number of times this endpoint was observed.
	Hits int
}

// Key is the identity used to dedup endpoints. Query and fragment are excluded
// on purpose -- they are per-request, not per-endpoint.
func (e Endpoint) Key() string {
	return e.Method + " " + e.Scheme + "://" + e.Host + e.Path
}

// Form is an HTML form discovered on a page. Forms are where user input crosses
// into the application, so they are first-class, not just another link.
type Form struct {
	// Page is the URL the form was found on.
	Page string
	// Action is the resolved absolute URL the form submits to.
	Action string
	Method string   // upper-case; defaults to GET when the form omits it
	Inputs []string // field names, sorted and de-duplicated
}

func (f Form) Key() string {
	return f.Method + " " + f.Action + " [" + strings.Join(f.Inputs, ",") + "]"
}

// World is the concurrency-safe store. The zero value is not usable; call New.
type World struct {
	mu        sync.Mutex
	endpoints map[string]*Endpoint
	forms     map[string]Form
	// visited records pages recon has already fetched, so a crawl does not loop.
	visited map[string]bool
}

func New() *World {
	return &World{
		endpoints: map[string]*Endpoint{},
		forms:     map[string]Form{},
		visited:   map[string]bool{},
	}
}

// MarkVisited records a page as fetched and returns false if it already was.
// Recon uses the return value to avoid re-crawling the same URL.
func (w *World) MarkVisited(rawURL string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.visited[rawURL] {
		return false
	}
	w.visited[rawURL] = true
	return true
}

// Observe records that a request to u (with the given method) happened and
// returned status. It returns nothing; the record is merged into the endpoint.
func (w *World) Observe(method string, u *url.URL, status int) {
	if u == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	e := &Endpoint{
		Method:   strings.ToUpper(method),
		Scheme:   strings.ToLower(u.Scheme),
		Host:     strings.ToLower(u.Hostname()),
		Path:     normalizePath(u),
		Params:   map[string]string{},
		Statuses: map[int]int{},
	}
	key := e.Key()
	existing, ok := w.endpoints[key]
	if !ok {
		w.endpoints[key] = e
		existing = e
	}
	existing.Hits++
	if status != 0 {
		existing.Statuses[status]++
	}
	for name, vals := range u.Query() {
		if len(vals) > 0 {
			existing.Params[name] = vals[len(vals)-1]
		} else {
			existing.Params[name] = ""
		}
	}
	if len(existing.Examples) < 5 {
		full := u.String()
		for _, ex := range existing.Examples {
			if ex == full {
				full = ""
				break
			}
		}
		if full != "" {
			existing.Examples = append(existing.Examples, full)
		}
	}
}

func normalizePath(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

// RecordForm stores a form, de-duplicated by action+method+inputs.
func (w *World) RecordForm(f Form) {
	f.Method = strings.ToUpper(strings.TrimSpace(f.Method))
	if f.Method == "" {
		f.Method = "GET"
	}
	f.Inputs = dedupSort(f.Inputs)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.forms[f.Key()] = f
}

// Endpoints returns all known endpoints, sorted by key for stable output.
func (w *World) Endpoints() []Endpoint {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]Endpoint, 0, len(w.endpoints))
	for _, e := range w.endpoints {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// Forms returns all known forms, sorted for stable output.
func (w *World) Forms() []Form {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]Form, 0, len(w.forms))
	for _, f := range w.forms {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// Counts is a quick summary for logs and the CLI.
func (w *World) Counts() (endpoints, forms, visited int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.endpoints), len(w.forms), len(w.visited)
}

func dedupSort(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
