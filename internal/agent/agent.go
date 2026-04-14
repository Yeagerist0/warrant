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
	"github.com/Yeagerist0/warrant/internal/llmrank"
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
// Ranking is the hand-written priority order (plan.Plan's own Priority field):
// equivalent to RunRanked with llmrank.Identity{}.
func Run(ctx context.Context, s *scope.Scope, seed string, ep execute.Policy, auditor egress.Auditor) (*Outcome, error) {
	return RunRanked(ctx, s, seed, ep, auditor, llmrank.Identity{})
}

// RunRanked is Run with the order of the planned actions handed to r before
// execution. r can only reorder what plan.Plan already produced -- see the
// llmrank package doc for why that is the whole point of the interface.
func RunRanked(ctx context.Context, s *scope.Scope, seed string, ep execute.Policy, auditor egress.Auditor, r llmrank.Ranker) (*Outcome, error) {
	client := egress.New(s, auditor)
	w := model.New()
	c := recon.New(s, client, w)
	if err := c.Crawl(ctx, []string{seed}); err != nil {
		return nil, err
	}
	actions := plan.Plan(w)
	if r != nil {
		// A Ranker is an ordering hint, not an authority to change the plan.
		// Give it a copy so an in-place mutation cannot alter our fallback.
		if ranked := r.Rank(append([]plan.Action(nil), actions...)); sameActions(actions, ranked) {
			actions = ranked
		}
	}
	results := execute.New(client, ep).Run(ctx, actions)

	eps, forms, _ := w.Counts()
	return &Outcome{Endpoints: eps, Forms: forms, Actions: actions, Results: results}, nil
}

// sameActions accepts only a permutation of the planner's exact actions.
// IDs are unique in plan.Plan, and Action contains only comparable fields.
func sameActions(planned, ranked []plan.Action) bool {
	if len(planned) != len(ranked) {
		return false
	}
	byID := make(map[string]plan.Action, len(planned))
	for _, a := range planned {
		byID[a.ID] = a
	}
	for _, a := range ranked {
		original, ok := byID[a.ID]
		if !ok || a != original {
			return false
		}
		delete(byID, a.ID)
	}
	return len(byID) == 0
}
