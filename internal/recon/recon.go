// Package recon walks the in-scope surface and writes what it finds into the
// world model. It is the first thing that actually moves through a target, so
// two properties matter more than cleverness:
//
//   - It cannot leave scope. Every request goes through the egress client,
//     which re-checks scope on every hop. Recon additionally pre-filters links
//     before enqueuing them, so an out-of-scope link is dropped quietly instead
//     of generating a refused request and audit-log noise for something we
//     never intended to fetch.
//   - It is bounded. A crawler with no page or depth limit is a denial-of-
//     service against your own target and a great way to get an engagement shut
//     down. MaxPages and MaxDepth are hard stops, not suggestions.
//
// HTML is extracted with regular expressions rather than a full DOM parser.
// That is a deliberate trade to keep the project dependency-free (standard
// library only); it finds hrefs, form actions and input names well enough to
// seed a planner, and it will miss links built by JavaScript. That limitation
// is real and stated, not hidden -- a recon pass is a starting map, not ground
// truth.
package recon

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Yeagerist0/warrant/internal/egress"
	"github.com/Yeagerist0/warrant/internal/model"
	"github.com/Yeagerist0/warrant/internal/scope"
)

type Crawler struct {
	client *egress.Client
	scope  *scope.Scope
	world  *model.World

	MaxPages int
	MaxDepth int
	// OnEvent, if set, receives one-line progress notes. Optional.
	OnEvent func(string)
}

func New(s *scope.Scope, c *egress.Client, w *model.World) *Crawler {
	return &Crawler{
		client:   c,
		scope:    s,
		world:    w,
		MaxPages: 50,
		MaxDepth: 3,
	}
}

func (c *Crawler) event(format string, args ...any) {
	if c.OnEvent != nil {
		c.OnEvent(fmt.Sprintf(format, args...))
	}
}

type item struct {
	url   string
	depth int
}

// Crawl BFS-walks from the seeds, staying in scope and within the page/depth
// limits, recording every fetched endpoint and every form into the world model.
func (c *Crawler) Crawl(ctx context.Context, seeds []string) error {
	queue := make([]item, 0, len(seeds))
	for _, s := range seeds {
		queue = append(queue, item{url: s, depth: 0})
	}

	fetched := 0
	for len(queue) > 0 {
		if fetched >= c.MaxPages {
			c.event("page limit (%d) reached; stopping", c.MaxPages)
			break
		}
		it := queue[0]
		queue = queue[1:]

		u, err := url.Parse(it.url)
		if err != nil {
			continue
		}
		// Pre-filter: don't even enqueue a fetch we know is out of scope.
		if d := c.scope.Check("GET", u); !d.Allowed {
			continue
		}
		if !c.world.MarkVisited(u.String()) {
			continue
		}

		resp, err := c.client.Do(ctx, "GET", u.String(), nil)
		if err != nil {
			c.event("skip %s: %v", u, err)
			continue
		}
		fetched++
		// Record the whole redirect chain, not just the final URL: each hop was
		// a real request and a real endpoint the agent touched.
		for _, hop := range resp.Hops {
			if hu, e := url.Parse(hop); e == nil {
				c.world.Observe("GET", hu, resp.Status)
			}
		}
		c.event("[%d/%d] %d %s", fetched, c.MaxPages, resp.Status, u)

		if !isHTML(resp.Header.Get("Content-Type")) {
			continue
		}
		base := finalURL(u, resp.Hops)
		body := string(resp.Body)

		for _, f := range extractForms(base, body) {
			c.world.RecordForm(f)
		}

		if it.depth >= c.MaxDepth {
			continue
		}
		for _, link := range extractLinks(base, body) {
			lu, err := url.Parse(link)
			if err != nil {
				continue
			}
			if d := c.scope.Check("GET", lu); !d.Allowed {
				continue
			}
			queue = append(queue, item{url: lu.String(), depth: it.depth + 1})
		}
	}
	eps, forms, visited := c.world.Counts()
	c.event("done: %d pages, %d endpoints, %d forms", visited, eps, forms)
	return nil
}

func isHTML(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/html")
}

// finalURL is the URL of the page whose body we actually got, i.e. the last hop.
func finalURL(requested *url.URL, hops []string) *url.URL {
	if len(hops) == 0 {
		return requested
	}
	if last, err := url.Parse(hops[len(hops)-1]); err == nil {
		return last
	}
	return requested
}

var (
	hrefRe = regexp.MustCompile(`(?i)<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)["']`)
	formRe = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	attrRe = func(name string) *regexp.Regexp {
		return regexp.MustCompile(`(?i)\b` + name + `\s*=\s*["']([^"']*)["']`)
	}
	inputRe = regexp.MustCompile(`(?is)<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']`)
)

// extractLinks resolves every <a href> against base and returns absolute
// http(s) URLs, fragment-stripped and de-duplicated.
func extractLinks(base *url.URL, body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(strings.ToLower(raw), "javascript:") ||
			strings.HasPrefix(strings.ToLower(raw), "mailto:") ||
			strings.HasPrefix(strings.ToLower(raw), "tel:") {
			continue
		}
		abs, err := base.Parse(raw)
		if err != nil {
			continue
		}
		if abs.Scheme != "http" && abs.Scheme != "https" {
			continue
		}
		abs.Fragment = ""
		s := abs.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// extractForms pulls each <form> with its resolved action, method and input
// field names.
func extractForms(base *url.URL, body string) []model.Form {
	actionRe := attrRe("action")
	methodRe := attrRe("method")
	var out []model.Form
	for _, m := range formRe.FindAllStringSubmatch(body, -1) {
		attrs, inner := m[1], m[2]

		action := base.String()
		if am := actionRe.FindStringSubmatch(attrs); am != nil && strings.TrimSpace(am[1]) != "" {
			if abs, err := base.Parse(strings.TrimSpace(am[1])); err == nil {
				abs.Fragment = ""
				action = abs.String()
			}
		}
		method := "GET"
		if mm := methodRe.FindStringSubmatch(attrs); mm != nil && strings.TrimSpace(mm[1]) != "" {
			method = strings.ToUpper(strings.TrimSpace(mm[1]))
		}
		var inputs []string
		for _, im := range inputRe.FindAllStringSubmatch(inner, -1) {
			inputs = append(inputs, im[1])
		}
		out = append(out, model.Form{
			Page:   base.String(),
			Action: action,
			Method: method,
			Inputs: inputs,
		})
	}
	return out
}
