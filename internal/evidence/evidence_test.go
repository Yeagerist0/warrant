package evidence

import "testing"

func proven(id string, k Kind, s Severity) Claim {
	return Claim{
		ID: id, Kind: k, Supports: s, Status: Observed,
		Text:     "demonstrated",
		Exhibits: []Exhibit{{ID: id + "-x", Replays: 2, Control: "same request, second account: 403"}},
	}
}

func TestCleanFindingIsReportable(t *testing.T) {
	f := Finding{
		Title:   "Cross-tenant read via predictable object id",
		Claimed: High,
		Claims: []Claim{
			proven("P1", Primitive, Medium),
			proven("I1", Impact, High),
		},
	}
	v := f.Review(DefaultPolicy())
	if !v.Reportable {
		t.Fatalf("expected reportable, got %v", v)
	}
	if v.Severity != High {
		t.Errorf("severity = %v, want high", v.Severity)
	}
}

// The Exodus shape: an endpoint genuinely answers without auth, but every
// request in the transcript addressed an identifier the tester generated.
// That is writing to your own channel, and it must not leave the building.
func TestVictimScopedPrimitiveNeedsObservedReachability(t *testing.T) {
	p := proven("P1", Primitive, Medium)
	p.VictimScoped = true
	f := Finding{
		Title:   "Unauthenticated write on pairing channel",
		Claimed: High,
		Claims: []Claim{
			p,
			{ID: "R1", Kind: Reachability, Status: Inferred, Supports: High,
				Text: "the channel id is derived from a value the product displays"},
		},
	}
	v := f.Review(DefaultPolicy())
	if v.Reportable {
		t.Fatalf("victim-scoped primitive with inferred reachability must not be reportable: %v", v)
	}
	found := false
	for _, b := range v.Blocking {
		if contains(b, "victim-scoped identifier") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the reachability gate to be the blocking reason, got %v", v.Blocking)
	}

	// Close the gap the way the lesson says to: find the disclosure and make
	// THAT the observed claim.
	f.Claims[1] = proven("R1", Reachability, High)
	if v := f.Review(DefaultPolicy()); !v.Reportable {
		t.Errorf("with observed reachability it should file: %v", v)
	}
}

// Self-addressed is fine when the primitive is not victim-scoped -- e.g. an
// unauthenticated endpoint that leaks global data. The gate must not fire.
func TestNonVictimScopedSkipsReachabilityGate(t *testing.T) {
	f := Finding{
		Title:   "Unauthenticated internal metrics endpoint",
		Claimed: Low,
		Claims:  []Claim{proven("P1", Primitive, Low)},
	}
	if v := f.Review(DefaultPolicy()); !v.Reportable {
		t.Fatalf("no victim identifier involved, gate should not fire: %v", v)
	}
}

// The Plaid shape: the interesting rating depends on a step that was reasoned
// about, not run. The finding still files, at the rating that was earned.
func TestUnprovenImpactCannotRaiseSeverity(t *testing.T) {
	f := Finding{
		Title:   "postMessage origin check bypass",
		Claimed: High,
		Claims: []Claim{
			proven("P1", Primitive, Medium),
			{ID: "I1", Kind: Impact, Status: Inferred, Supports: Critical,
				Text: "integrations that trust the callback would exchange an attacker token"},
		},
	}
	v := f.Review(DefaultPolicy())
	if !v.Reportable {
		t.Fatalf("should still be reportable at the earned rating: %v", v)
	}
	if v.Severity != Medium {
		t.Errorf("severity = %v, want medium (the executed ceiling)", v.Severity)
	}
	if len(v.Reductions) == 0 {
		t.Error("expected the downgrade to be recorded, not silent")
	}
	if len(v.Notes) == 0 {
		t.Error("the unproven critical claim should survive as a labelled note")
	}
}

func TestSingleHitIsNotEvidence(t *testing.T) {
	c := proven("P1", Primitive, High)
	c.Exhibits[0].Replays = 1
	f := Finding{Title: "flaky", Claimed: High, Claims: []Claim{c}}
	if v := f.Review(DefaultPolicy()); v.Reportable {
		t.Errorf("one reproduction should not clear a 2-replay policy: %v", v)
	}
}

func TestMissingControlBlocks(t *testing.T) {
	c := proven("P1", Primitive, High)
	c.Exhibits[0].Control = ""
	f := Finding{Title: "no control", Claimed: High, Claims: []Claim{c}}
	v := f.Review(DefaultPolicy())
	if v.Reportable {
		t.Errorf("a primitive with no negative control should block: %v", v)
	}
}

func TestNothingObservedIsNotAFinding(t *testing.T) {
	f := Finding{
		Title:   "vibes",
		Claimed: Critical,
		Claims: []Claim{
			{ID: "P1", Kind: Primitive, Status: Inferred, Supports: Critical},
			{ID: "I1", Kind: Impact, Status: Untested, Supports: Critical},
		},
	}
	v := f.Review(DefaultPolicy())
	if v.Reportable || v.Severity != None {
		t.Errorf("an all-inferred finding must not file: %v", v)
	}
}

func TestRefutedClaimEarnsNothing(t *testing.T) {
	f := Finding{
		Title:   "disproved",
		Claimed: High,
		Claims: []Claim{
			proven("P1", Primitive, Low),
			{ID: "I1", Kind: Impact, Status: Refuted, Supports: Critical},
		},
	}
	v := f.Review(DefaultPolicy())
	if v.Severity != Low {
		t.Errorf("severity = %v, want low; a refuted claim must not count", v.Severity)
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
