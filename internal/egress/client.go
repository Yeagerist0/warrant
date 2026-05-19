// Package egress is the only way this program reaches the network.
//
// Everything here exists to make one property true: no byte leaves the process
// for a destination the scope file did not authorize. That is easy to state and
// easy to get wrong, because the interesting violations are not the request you
// wrote -- they are the hop you did not.
//
// A 302 to a different host is a new request to a new party. Go's default
// client will follow it for you, cheerfully, and the first time you learn the
// target redirects to a third-party SSO tenant is when that tenant's owner asks
// why you were scanning them. So every hop is re-checked, and a redirect that
// leaves scope is a hard stop rather than a silently dropped header.
package egress

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Yeagerist0/warrant/internal/scope"
)

// Auditor receives every decision, allowed or refused. The refusals are the
// half that proves the agent stayed inside the engagement, so they are not
// debug output -- they are the record.
type Auditor interface {
	Record(method string, u *url.URL, d scope.Decision)
}

type Client struct {
	scope *scope.Scope
	http  *http.Client
	audit Auditor

	// MaxRedirects bounds a redirect chain independently of scope, so a loop
	// inside an authorized host cannot spin forever.
	MaxRedirects int
	// UserAgent identifies the tool and the engagement. Testing anonymously is
	// how you get blocked and how you make a defender's night worse for no
	// reason; a program that sees this string can find you.
	UserAgent string

	mu   sync.Mutex
	last time.Time
	gap  time.Duration
}

func New(s *scope.Scope, a Auditor) *Client {
	gap := time.Duration(0)
	if s.MaxRPS > 0 {
		gap = time.Duration(float64(time.Second) / s.MaxRPS)
	}
	return &Client{
		scope: s,
		audit: a,
		http: &http.Client{
			Timeout: 20 * time.Second,
			// Redirects are followed by hand so each hop can be checked.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		MaxRedirects: 5,
		UserAgent:    "warrant/0.1 (authorized security testing; " + s.Engagement + ")",
		gap:          gap,
	}
}

// OutOfScopeError is returned rather than swallowed, because the caller
// deciding what to do about a refused destination is a design decision, not a
// transport detail.
type OutOfScopeError struct {
	Method string
	URL    string
	Reason string
	// ViaRedirect is set when scope was left partway through a chain, which is
	// the case worth shouting about in a report.
	ViaRedirect bool
}

func (e *OutOfScopeError) Error() string {
	if e.ViaRedirect {
		return fmt.Sprintf("refused redirect to %s %s: %s", e.Method, e.URL, e.Reason)
	}
	return fmt.Sprintf("refused %s %s: %s", e.Method, e.URL, e.Reason)
}

// Response is a fully-read exchange, kept together with the hops it took so a
// finding can cite the chain rather than just the endpoint.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	Hops   []string
}

func (c *Client) throttle() {
	if c.gap == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if wait := c.gap - time.Since(c.last); wait > 0 {
		time.Sleep(wait)
	}
	c.last = time.Now()
}

// Do issues a request, following redirects only while every hop stays in scope.
func (c *Client) Do(ctx context.Context, method string, raw string, body io.Reader) (*Response, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", raw, err)
	}

	hops := []string{}
	for i := 0; ; i++ {
		d := c.scope.Check(method, u)
		if c.audit != nil {
			c.audit.Record(method, u, d)
		}
		if !d.Allowed {
			return nil, &OutOfScopeError{
				Method: method, URL: u.String(), Reason: d.Reason,
				ViaRedirect: i > 0,
			}
		}

		c.throttle()
		req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", c.UserAgent)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		hops = append(hops, u.String())

		loc := resp.Header.Get("Location")
		isRedirect := resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != ""
		if !isRedirect {
			b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
			resp.Body.Close()
			if err != nil {
				return nil, err
			}
			return &Response{Status: resp.StatusCode, Header: resp.Header, Body: b, Hops: hops}, nil
		}

		resp.Body.Close()
		if i >= c.MaxRedirects {
			return nil, fmt.Errorf("redirect limit (%d) reached starting at %s", c.MaxRedirects, hops[0])
		}
		next, err := u.Parse(loc) // resolves relative Location against the current URL
		if err != nil {
			return nil, fmt.Errorf("bad Location %q: %w", loc, err)
		}
		u = next
		// A redirected request body cannot be replayed, and re-sending one to a
		// new endpoint is its own hazard. Follow as a GET, as browsers do for
		// 301/302/303.
		if resp.StatusCode != 307 && resp.StatusCode != 308 {
			method, body = http.MethodGet, nil
		} else if body != nil {
			return nil, fmt.Errorf("cannot replay request body across a %d redirect to %s", resp.StatusCode, u)
		}
	}
}
