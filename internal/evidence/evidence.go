// Package evidence is the part of this agent that says no.
//
// An autonomous attacker is very good at producing plausible sentences about
// what it might have achieved. The expensive failure is not a missed bug, it is
// a confident report of a bug that was never demonstrated -- that is what burns
// a triage relationship and what gets a report closed Informative.
//
// So findings are not prose here. A finding is a set of typed claims, each one
// carrying its own status and its own exhibits, and the reporter refuses to
// print a severity that the observed claims do not already support. Two rules
// are enforced mechanically because both were learned the expensive way:
//
//  1. Reachability. "This endpoint has no auth" is half a finding. The other
//     half is how an attacker addresses a *victim's* instance of it. A report
//     that only ever addressed an identifier the tester generated themselves
//     demonstrates writing to your own channel, and triage will say so.
//
//  2. Severity is capped by what was executed. An impact claim that was
//     reasoned about rather than run cannot raise the rating. It stays in the
//     report, labelled, because the gap is useful information -- but it is not
//     allowed to move the number.
package evidence

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Status string

const (
	// Observed: reproduced from a recorded request/response pair.
	Observed Status = "observed"
	// Inferred: follows from observed facts, but no one executed it.
	Inferred Status = "inferred"
	// Untested: named as a possibility and left alone.
	Untested Status = "untested"
	// Refuted: tried, and the target did not behave that way.
	Refuted Status = "refuted"
)

type Kind string

const (
	// Primitive is the raw behaviour: what the target actually did.
	Primitive Kind = "primitive"
	// Reachability answers: from an internet position, how does an attacker
	// address the victim's instance of this?
	Reachability Kind = "reachability"
	// Impact is the consequence that a severity rating leans on.
	Impact Kind = "impact"
)

type Severity int

const (
	None Severity = iota
	Informational
	Low
	Medium
	High
	Critical
)

var sevNames = map[Severity]string{
	None: "none", Informational: "informational", Low: "low",
	Medium: "medium", High: "high", Critical: "critical",
}

func (s Severity) String() string {
	if n, ok := sevNames[s]; ok {
		return n
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// Exhibit is one recorded interaction. Replays is how many independent times
// the same request produced the same relevant behaviour -- a single hit on a
// race or a flaky endpoint is a coincidence until it repeats.
type Exhibit struct {
	ID       string `json:"id"`
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	Replays  int    `json:"replays"`
	// Control records the negative case, e.g. the same request without the
	// token, or as a second account. A claim with no control is a claim that
	// has not ruled out "it does that for everyone".
	Control string `json:"control,omitempty"`
}

type Claim struct {
	ID   string `json:"id"`
	Text string `json:"text"`
	Kind Kind   `json:"kind"`
	// Supports is the severity this claim would justify if it is Observed.
	Supports Severity  `json:"supports"`
	Status   Status    `json:"status"`
	Exhibits []Exhibit `json:"exhibits,omitempty"`
	// VictimScoped marks a primitive that operates on an identifier belonging
	// to someone else. Setting it turns on the reachability gate.
	VictimScoped bool `json:"victim_scoped,omitempty"`
}

func (c Claim) replays() int {
	n := 0
	for _, e := range c.Exhibits {
		n += e.Replays
	}
	return n
}

func (c Claim) hasControl() bool {
	for _, e := range c.Exhibits {
		if strings.TrimSpace(e.Control) != "" {
			return true
		}
	}
	return false
}

// UnmarshalJSON lets a finding file say "high" rather than 4. A finding is
// something a human reads and edits; magic integers in that file would be a
// transcription error waiting to happen.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return fmt.Errorf("severity must be a string such as \"high\": %w", err)
	}
	for sev, n := range sevNames {
		if strings.EqualFold(n, name) {
			*s = sev
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", name)
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Status) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	switch Status(strings.ToLower(name)) {
	case Observed, Inferred, Untested, Refuted:
		*s = Status(strings.ToLower(name))
		return nil
	}
	return fmt.Errorf("unknown status %q (want observed, inferred, untested or refuted)", name)
}

func (k *Kind) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	switch Kind(strings.ToLower(name)) {
	case Primitive, Reachability, Impact:
		*k = Kind(strings.ToLower(name))
		return nil
	}
	return fmt.Errorf("unknown claim kind %q (want primitive, reachability or impact)", name)
}

type Finding struct {
	Title string `json:"title"`
	// Claimed is what the agent wants to report. Review may lower it.
	Claimed Severity `json:"claimed"`
	Claims  []Claim  `json:"claims"`
}

// Policy is the evidentiary bar. Defaults are deliberately strict.
type Policy struct {
	MinReplays          int  // independent reproductions required per observed primitive
	RequireControl      bool // an observed primitive must have a negative control
	RequireReachability bool
}

func DefaultPolicy() Policy {
	return Policy{MinReplays: 2, RequireControl: true, RequireReachability: true}
}

// Verdict is the reviewed finding: what may be reported, at what rating, and
// every reason the agent's own claim was cut down.
type Verdict struct {
	Reportable bool
	Severity   Severity
	// Blocking are the reasons a finding cannot be filed at all.
	Blocking []string
	// Reductions are the reasons the rating is below what was claimed.
	Reductions []string
	// Notes are things worth writing in the report but not acted on.
	Notes []string
}

func (v Verdict) String() string {
	var b strings.Builder
	if v.Reportable {
		fmt.Fprintf(&b, "reportable at %s", v.Severity)
	} else {
		b.WriteString("not reportable")
	}
	for _, r := range v.Blocking {
		fmt.Fprintf(&b, "\n  blocked: %s", r)
	}
	for _, r := range v.Reductions {
		fmt.Fprintf(&b, "\n  reduced: %s", r)
	}
	for _, r := range v.Notes {
		fmt.Fprintf(&b, "\n  note: %s", r)
	}
	return b.String()
}

// Review applies the policy. It never raises a rating and never invents a
// claim; the only thing it can do is refuse and explain.
func (f *Finding) Review(p Policy) Verdict {
	var v Verdict

	var primitives, reaches []Claim
	for _, c := range f.Claims {
		switch c.Kind {
		case Primitive:
			primitives = append(primitives, c)
		case Reachability:
			reaches = append(reaches, c)
		}
	}

	observedPrimitive := false
	victimScoped := false
	for _, c := range primitives {
		if c.VictimScoped {
			victimScoped = true
		}
		if c.Status != Observed {
			continue
		}
		if c.replays() < p.MinReplays {
			v.Blocking = append(v.Blocking, fmt.Sprintf(
				"claim %s is marked observed but reproduced %d time(s); policy requires %d",
				c.ID, c.replays(), p.MinReplays))
			continue
		}
		if p.RequireControl && !c.hasControl() {
			v.Blocking = append(v.Blocking, fmt.Sprintf(
				"claim %s has no negative control, so 'the target does this for everyone' is not ruled out", c.ID))
			continue
		}
		observedPrimitive = true
	}

	if len(primitives) == 0 {
		v.Blocking = append(v.Blocking, "no primitive claim: nothing was demonstrated about the target's behaviour")
	} else if !observedPrimitive {
		v.Blocking = append(v.Blocking, "no primitive claim reached observed status with sufficient evidence")
	}

	// The reachability gate. Only armed when the primitive operates on someone
	// else's identifier -- a self-addressed channel is a design note, not a bug.
	if p.RequireReachability && victimScoped {
		ok := false
		for _, c := range reaches {
			if c.Status == Observed {
				ok = true
			}
		}
		if !ok {
			v.Blocking = append(v.Blocking, "primitive operates on a victim-scoped identifier, "+
				"but no observed claim shows where an attacker obtains that identifier from an internet position; "+
				"find the disclosure and make that the finding, or do not file")
		}
	}

	// Severity is the ceiling of what was actually executed.
	earned := None
	for _, c := range f.Claims {
		if c.Status == Observed && c.Supports > earned {
			earned = c.Supports
		}
	}
	for _, c := range f.Claims {
		if c.Status != Observed && c.Supports > earned {
			v.Notes = append(v.Notes, fmt.Sprintf(
				"claim %s would support %s but is %s; stated as unproven, not counted toward the rating",
				c.ID, c.Supports, c.Status))
		}
	}
	sort.Strings(v.Notes)

	v.Severity = f.Claimed
	if earned < f.Claimed {
		v.Reductions = append(v.Reductions, fmt.Sprintf(
			"claimed %s, but observed evidence supports %s", f.Claimed, earned))
		v.Severity = earned
	}

	v.Reportable = len(v.Blocking) == 0 && v.Severity > None
	if len(v.Blocking) == 0 && v.Severity == None {
		v.Blocking = append(v.Blocking, "no observed claim supports any severity above none")
		v.Reportable = false
	}
	return v
}
