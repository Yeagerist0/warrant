// Command warrant is an autonomous web-application testing agent that is not
// allowed to act outside its authorization, and not allowed to report what it
// did not demonstrate.
//
// This binary currently exposes the enforcement spine directly, so the parts
// that say no can be exercised and audited on their own, before any planner is
// wired in front of them. The subcommands are deliberately boring:
//
//	warrant scope  <scope.json> <method> <url>   -- would this be allowed, and why
//	warrant fetch  <scope.json> <method> <url>   -- issue it, re-checking every redirect hop
//	warrant review <finding.json>                -- apply the evidence policy to a finding
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Yeagerist0/warrant/internal/egress"
	"github.com/Yeagerist0/warrant/internal/evidence"
	"github.com/Yeagerist0/warrant/internal/scope"
)

const usage = `warrant -- authorized web testing agent

  warrant scope  <scope.json> <method> <url>   is this in scope, and why
  warrant fetch  <scope.json> <method> <url>   request it, checking every redirect hop
  warrant review <finding.json>                apply the evidence policy

Every scope file must name an engagement and the authority it was tested under.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scope":
		err = cmdScope(os.Args[2:])
	case "fetch":
		err = cmdFetch(os.Args[2:])
	case "review":
		err = cmdReview(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "warrant:", err)
		os.Exit(1)
	}
}

// stderrAuditor prints every decision as it is made. Allowed and refused both:
// the refusals are the evidence the engagement was respected.
type stderrAuditor struct{}

func (stderrAuditor) Record(method string, u *url.URL, d scope.Decision) {
	fmt.Fprintf(os.Stderr, "[audit] %s\n", d)
}

func cmdScope(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: warrant scope <scope.json> <method> <url>")
	}
	s, err := scope.Load(args[0])
	if err != nil {
		return err
	}
	u, err := url.Parse(args[2])
	if err != nil {
		return err
	}
	d := s.Check(strings.ToUpper(args[1]), u)
	fmt.Printf("engagement: %s\nauthority:  %s\n\n%s\n", s.Engagement, s.Authority, d)
	if !d.Allowed {
		os.Exit(3) // distinct from an error: the tool worked, the answer was no
	}
	return nil
}

func cmdFetch(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: warrant fetch <scope.json> <method> <url>")
	}
	s, err := scope.Load(args[0])
	if err != nil {
		return err
	}
	c := egress.New(s, stderrAuditor{})
	resp, err := c.Do(context.Background(), strings.ToUpper(args[1]), args[2], nil)
	if err != nil {
		return err
	}
	fmt.Printf("%d  (%d bytes)\n", resp.Status, len(resp.Body))
	if len(resp.Hops) > 1 {
		fmt.Println("chain:")
		for _, h := range resp.Hops {
			fmt.Println("  ->", h)
		}
	}
	return nil
}

func cmdReview(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: warrant review <finding.json>")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var f evidence.Finding
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	v := f.Review(evidence.DefaultPolicy())
	fmt.Printf("%s\n\n%s\n", f.Title, v)
	if !v.Reportable {
		os.Exit(3)
	}
	return nil
}
