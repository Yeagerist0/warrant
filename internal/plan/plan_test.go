package plan

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Yeagerist0/warrant/internal/model"
)

func obs(w *model.World, method, raw string, status int) {
	u, _ := url.Parse(raw)
	w.Observe(method, u, status)
}

func byKind(actions []Action, k Kind) []Action {
	var out []Action
	for _, a := range actions {
		if a.Kind == k {
			out = append(out, a)
		}
	}
	return out
}

func TestIDLikeParamProducesTamperAction(t *testing.T) {
	w := model.New()
	obs(w, "GET", "https://api.example.com/users?id=5", 200)
	actions := Plan(w)

	tampers := byKind(actions, ParamTamper)
	if len(tampers) != 1 {
		t.Fatalf("expected 1 param-tamper action, got %d: %+v", len(tampers), actions)
	}
	a := tampers[0]
	if a.Param != "id" {
		t.Errorf("param = %q, want id", a.Param)
	}
	if !strings.Contains(a.URL, "id=4") {
		t.Errorf("expected decremented id in URL, got %s", a.URL)
	}
	if !a.Safe {
		t.Error("a GET id-tamper is read-only and should be marked Safe")
	}
}

func TestNonIDParamIsNotTampered(t *testing.T) {
	w := model.New()
	obs(w, "GET", "https://x.com/search?q=hello", 200)
	if got := len(byKind(Plan(w), ParamTamper)); got != 0 {
		t.Errorf("q is not an identifier; expected 0 tamper actions, got %d", got)
	}
}

func TestTamperOnlyOnEndpointsThatAnswered(t *testing.T) {
	w := model.New()
	obs(w, "GET", "https://x.com/users?id=5", 404) // never answered OK
	if got := len(byKind(Plan(w), ParamTamper)); got != 0 {
		t.Errorf("endpoint only 404'd; tampering proves nothing, want 0 got %d", got)
	}
}

func TestSensitivePathProducesUnauthProbeRankedFirst(t *testing.T) {
	w := model.New()
	obs(w, "GET", "https://x.com/admin/settings", 200)
	obs(w, "GET", "https://x.com/public/home", 200)
	actions := Plan(w)

	unauth := byKind(actions, MissingAuth)
	if len(unauth) != 1 {
		t.Fatalf("expected 1 missing-auth action (only /admin is sensitive), got %d", len(unauth))
	}
	// The unauth-reach class is the highest paying, so it should be first.
	if actions[0].Kind != MissingAuth {
		t.Errorf("missing-auth should rank first, got %s first", actions[0].Kind)
	}
}

func TestGetEndpointGetsMethodProbe(t *testing.T) {
	w := model.New()
	obs(w, "GET", "https://x.com/thing", 200)
	mp := byKind(Plan(w), MethodProbe)
	if len(mp) != 1 || mp[0].Method != "OPTIONS" || !mp[0].Safe {
		t.Errorf("expected one safe OPTIONS method-probe, got %+v", mp)
	}
}

func TestOneSecurityHeaderCheckPerHost(t *testing.T) {
	w := model.New()
	obs(w, "GET", "https://x.com/a", 200)
	obs(w, "GET", "https://x.com/b", 200)
	obs(w, "GET", "https://y.com/a", 200)
	sh := byKind(Plan(w), SecurityHeaders)
	if len(sh) != 2 {
		t.Errorf("expected one header check per host (2), got %d", len(sh))
	}
}

func TestFormSubmitIsNotSafeAndAuthFormFlagged(t *testing.T) {
	w := model.New()
	obs(w, "GET", "https://x.com/login", 200)
	w.RecordForm(model.Form{Page: "https://x.com/login", Action: "https://x.com/login", Method: "POST", Inputs: []string{"username", "password"}})
	var formAction *Action
	for _, a := range Plan(w) {
		if strings.HasPrefix(a.ID, "form:") {
			aa := a
			formAction = &aa
		}
	}
	if formAction == nil {
		t.Fatal("expected a form action")
	}
	if formAction.Safe {
		t.Error("submitting a form changes state; must not be Safe")
	}
	if !strings.Contains(strings.ToLower(formAction.Rationale), "credential") {
		t.Errorf("a password form should flag credential handling: %q", formAction.Rationale)
	}
}

func TestDeterministicAndDeduped(t *testing.T) {
	w := model.New()
	obs(w, "GET", "https://x.com/users?id=9", 200)
	obs(w, "GET", "https://x.com/users?id=9", 200) // same endpoint twice
	a1 := Plan(w)
	a2 := Plan(w)
	if len(a1) != len(a2) {
		t.Fatalf("plan is not deterministic: %d vs %d", len(a1), len(a2))
	}
	ids := map[string]bool{}
	for _, a := range a1 {
		if ids[a.ID] {
			t.Errorf("duplicate action id %q", a.ID)
		}
		ids[a.ID] = true
	}
}

func TestPriorityOrdering(t *testing.T) {
	w := model.New()
	obs(w, "GET", "https://x.com/admin?id=3", 200)
	actions := Plan(w)
	for i := 1; i < len(actions); i++ {
		if actions[i-1].Priority < actions[i].Priority {
			t.Errorf("actions not sorted by priority desc at %d: %d < %d",
				i, actions[i-1].Priority, actions[i].Priority)
		}
	}
}
