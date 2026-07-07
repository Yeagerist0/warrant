// Package agent runs the whole loop end to end: recon builds the map, the
// planner ranks what is worth trying, the executor runs the safe probes through
// the scope-gated egress client, and the evidence ledger judges what came back.
//
// It exists so the pipeline is one testable function instead of logic buried in
// main. The measurement that matters for this project -- against a target with
// known bugs, how many findings does the agent file, and how many does the
// ledger refuse before they reach a report -- is just this function run against
// a known app and counted. That test lives next door.
package agent

import (
	"context"

	"github.com/Yeagerist0/warrant/internal/egress"
	"github.com/Yeagerist0/warrant/internal/execute"
	"github.com/Yeagerist0/warrant/internal/model"
	"github.com/Yeagerist0/warrant/internal/plan"
	"github.com/Yeagerist0/warrant/internal/recon"
	"github.com/Yeagerist0/warrant/internal/scope"
)

// Outcome is everything the loop produced, kept together so a caller (the CLI,
// a test, a future report writer) can summarise it however it needs.
type Outcome struct {
	Endpoints int
	Forms     int
	Actions   []plan.Action
	Results   []execute.Result
}

// Summary counts the results the way the project cares about: how many probes
// ran, how many were held for confirmation, and -- the number that is the whole
// point -- how many findings the ledger cleared versus refused.
func (o *Outcome) Summary() (executed, skipped, reportable, refused int) {
	for _, r := range o.Results {
		switch {
		case r.Skipped:
			skipped++
		case r.Err != nil:
			// errors are neither executed successfully nor skipped-by-policy
		case r.Finding != nil:
			executed++
			if r.Verdict.Reportable {
				reportable++
			} else {
				refused++
			}
		default:
			executed++
		}
	}
	return
}

// Run performs recon from the seed, plans, and executes the safe probes.
// auditor may be nil. The seed is scope-checked before anything is fetched.
func Run(ctx context.Context, s *scope.Scope, seed string, ep execute.Policy, auditor egress.Auditor) (*Outcome, error) {
	client := egress.New(s, auditor)
	w := model.New()
	c := recon.New(s, client, w)
	if err := c.Crawl(ctx, []string{seed}); err != nil {
		return nil, err
	}
	actions := plan.Plan(w)
	results := execute.New(client, ep).Run(ctx, actions)

	eps, forms, _ := w.Counts()
	return &Outcome{Endpoints: eps, Forms: forms, Actions: actions, Results: results}, nil
}
