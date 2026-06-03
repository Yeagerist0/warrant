// Command warrant rankeval measures what llmrank actually changes: given a
// fixed target, does re-ranking by a model move the genuine unauth/IDOR
// probes any earlier (or later) in the plan than the hand-written priorities
// already put them, and -- the property that actually matters -- does
// changing the order change what the evidence ledger reports.
//
// The target is a local fixture with a known bug list, the same discipline as
// internal/agent's precision test: three genuine unauthenticated-reach/IDOR
// endpoints buried among seventeen decoys (blog posts, a search page, a
// contact form, a login form), so a ranking that actually degraded attention
// would be visible as those three sliding down the list.
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"

	"github.com/Yeagerist0/warrant/internal/agent"
	"github.com/Yeagerist0/warrant/internal/execute"
	"github.com/Yeagerist0/warrant/internal/llmrank"
	"github.com/Yeagerist0/warrant/internal/plan"
	"github.com/Yeagerist0/warrant/internal/scope"
)

// rankevalApp is the fixture. Three genuine bugs:
//   - /admin/users?id=42         unauthenticated reach + IDOR (sensitive path, id param)
//   - /account?account_id=1001   unauthenticated reach + IDOR (sensitive path, account_id param)
//   - /api/orders?order_id=77    IDOR only (sensitive path via "/api/", id-shaped param)
//
// Seventeen decoys: ten blog posts, search, about, contact (GET + a no-secret
// POST form), login (GET + a password POST form), and the one
// security-headers check every host gets once. None of those is sensitive or
// id-tampered by plan's own rules, so they should all rank below the three
// bugs under either ranker -- that is what this eval checks.
func rankevalApp() *httptest.Server {
	mux := http.NewServeMux()
	var links string
	links += `<a href="/admin/users?id=42">admin</a>`
	links += `<a href="/account?account_id=1001">account</a>`
	links += `<a href="/api/orders?order_id=77">orders</a>`
	links += `<a href="/search?q=x">search</a>`
	links += `<a href="/about">about</a>`
	links += `<a href="/contact">contact</a>`
	links += `<a href="/login">login</a>`
	for i := 1; i <= 10; i++ {
		links += fmt.Sprintf(`<a href="/blog/%d">post %d</a>`, i, i)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", links)
	})
	mux.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "USER %s: secret-token", r.URL.Query().Get("id"))
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ACCOUNT %s", r.URL.Query().Get("account_id"))
	})
	mux.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ORDER %s", r.URL.Query().Get("order_id"))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "results for x") })
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "about us") })
	mux.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `<form action="/contact" method="post"><input name="email"><input name="message"></form>`)
		}
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `<form action="/login" method="post"><input name="username"><input name="password"></form>`)
		}
	})
	for i := 1; i <= 10; i++ {
		mux.HandleFunc(fmt.Sprintf("/blog/%d", i), func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "post body") })
	}
	return httptest.NewServer(mux)
}

func isGenuineBug(a plan.Action) bool {
	switch a.Kind {
	case plan.MissingAuth, plan.ParamTamper:
		return true
	}
	return false
}

func rankPositions(actions []plan.Action) []int {
	var out []int
	for i, a := range actions {
		if isGenuineBug(a) {
			out = append(out, i+1) // 1-based
		}
	}
	return out
}

func mean(xs []int) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0
	for _, x := range xs {
		sum += x
	}
	return float64(sum) / float64(len(xs))
}

func cmdRankEval(args []string) error {
	key := os.Getenv("WARRANT_LLM_API_KEY")
	if key == "" {
		return fmt.Errorf("rankeval: set WARRANT_LLM_API_KEY (an OpenAI-compatible endpoint's key, e.g. a Gemini key)")
	}
	llm := &llmrank.LLMRanker{
		BaseURL:         envOr("WARRANT_LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai"),
		APIKey:          key,
		ModelName:       envOr("WARRANT_LLM_MODEL", "gemini-3.1-flash-lite"),
		ReasoningEffort: envOr("WARRANT_LLM_REASONING_EFFORT", "none"),
	}

	srv := rankevalApp()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	s := &scope.Scope{
		Engagement: "rankeval", Authority: "baked-in fixture, local only", AllowPrivate: true,
		Allow: []scope.Rule{{Host: u.Hostname(), Ports: []int{port}}},
	}

	ctx := context.Background()
	ruleOut, err := agent.RunRanked(ctx, s, srv.URL+"/", execute.DefaultPolicy(), nil, llmrank.Identity{})
	if err != nil {
		return fmt.Errorf("rule-ranked run: %w", err)
	}
	llmOut, err := agent.RunRanked(ctx, s, srv.URL+"/", execute.DefaultPolicy(), nil, llm)
	if err != nil {
		return fmt.Errorf("llm-ranked run: %w", err)
	}

	ruleExec, ruleSkip, ruleReport, ruleRefused := ruleOut.Summary()
	llmExec, llmSkip, llmReport, llmRefused := llmOut.Summary()
	rulePos := rankPositions(ruleOut.Actions)
	llmPos := rankPositions(llmOut.Actions)

	fmt.Printf("rankeval: %d actions total, %d of them the genuine unauth/IDOR bugs (3 planted endpoints, "+
		"each sensitive-path AND id-tampered so each yields an unauth + an idor action)\n\n",
		len(ruleOut.Actions), len(rulePos))
	fmt.Printf("hand-written priority: positions %v, mean %.1f | executed=%d skipped=%d reportable=%d refused=%d\n",
		rulePos, mean(rulePos), ruleExec, ruleSkip, ruleReport, ruleRefused)
	fmt.Printf("LLM-ranked (%s):  positions %v, mean %.1f | executed=%d skipped=%d reportable=%d refused=%d\n",
		llm.ModelName, llmPos, mean(llmPos), llmExec, llmSkip, llmReport, llmRefused)
	fmt.Printf("\nmodel calls=%d failures=%d", llm.Calls, llm.Failures)
	if llm.LastErr != nil {
		fmt.Printf(" last_err=%v", llm.LastErr)
	}
	fmt.Println()

	if ruleReport != llmReport || ruleRefused != llmRefused {
		fmt.Println("\nNOTE: reportable/refused counts differ between rankings -- ranking should only " +
			"change ORDER, never what the ledger decides. This would be a bug, not an LLM finding.")
	} else {
		fmt.Println("\nreportable/refused counts match exactly between rankings, as they must: " +
			"llmrank can only reorder plan.Plan's output, so the evidence ledger's verdicts are unaffected " +
			"by which ranker ran.")
	}
	return nil
}
