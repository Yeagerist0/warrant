# warrant

An autonomous web-application testing agent that can't act outside its authorization and can't report what it didn't demonstrate.

Both halves are enforced in code, not in a prompt. That's the whole idea: an agent that plans its own actions will eventually plan one nobody authorized, and it will always be able to write a confident paragraph about a bug it never proved.

## Status

The enforcement spine is built and tested — scope, egress, evidence — and on top of it, recon that maps a target into a world model, a planner that ranks probes, and an executor that runs the safe ones and hands each result to the evidence ledger. The loop is closed. I'm building it in this order on purpose, because the parts that say *no* are the parts that have to be right before anything starts acting on its own.

59 tests, `go test ./...` (race-clean).

## Why it works this way

I've had two reports go badly in ways that a tool could have caught.

One was closed Informative because every request in my transcript addressed an identifier I had generated myself. The endpoint really did accept unauthenticated writes. But I never showed how an attacker reaches *someone else's* channel, so what I actually demonstrated was writing to my own. Triage said so, and they were right.

The other was a finding whose interesting severity depended on a step I'd reasoned about instead of running. I downgraded it to match the evidence. That was also wrong — the evidence was obtainable the whole time, in the vendor's own published reference integration. The lesson wasn't "claim less", it was "go get the thing that closes the gap."

So findings here aren't prose. A finding is a set of typed claims, each carrying its own status and its own exhibits, and the reviewer refuses to print a severity that the observed claims don't already support.

```
$ warrant review examples/finding.reachability-gap.json
Unauthenticated write on the pairing channel

not reportable
  blocked: primitive operates on a victim-scoped identifier, but no observed claim
           shows where an attacker obtains that identifier from an internet position;
           find the disclosure and make that the finding, or do not file
  reduced: claimed high, but observed evidence supports medium
  note:    claim R1 would support high but is inferred; stated as unproven,
           not counted toward the rating
```

The gate only arms when the primitive touches an identifier belonging to someone else. An unauthenticated endpoint leaking global data doesn't need a reachability story, and a tool that demanded one would just be wrong.

Three other rules, all the same shape:

- A claim marked observed with one reproduction isn't observed. Default policy wants two.
- A primitive with no negative control hasn't ruled out "the target does that for everyone."
- Unproven claims stay in the report, labelled, and can't move the number.

## Scope

Default deny. Deny rules beat allow rules, because an exclusion is in the file for a reason and no allow rule should be able to reopen it. `*.example.com` matches subdomains and not the apex, the way bug-bounty scopes are actually written — the apex is often a different app with a different owner.

Every scope file has to name the authority it was tested under, or it won't load:

```json
{
  "engagement": "juice-shop-local",
  "authority": "Locally hosted OWASP Juice Shop, intentionally vulnerable, run by me on my own machine. No third-party system is in scope.",
  "allow_private": true,
  "allow": [{ "host": "127.0.0.1", "ports": [3000], "note": "the Juice Shop container" }],
  "deny":  [{ "host": "127.0.0.1", "paths": ["/ftp/"] }]
}
```

Private and loopback addresses are blocked unless you opt in, so a scope written for a public target can't be turned inward by a redirect or a hostname that resolves to 127.0.0.1.

## Redirects are where scope actually leaks

A 302 to another host is a new request to a new party, and Go's default client will follow it for you without asking. The first time you find out your target redirects to a third-party SSO tenant is when that tenant's owner asks why you were scanning them.

So every hop is re-checked and a redirect that leaves scope is a hard error, not a dropped header:

```go
_, err := c.Do(ctx, "GET", target+"/login", nil)
// refused redirect to GET https://sso.vendor.example/: sso.vendor.example
// is not named in the scope file (default deny)
```

Writing the test for this is how I found a bug in my own design. Two `httptest` servers both live on 127.0.0.1, so my host-only scope rule authorized the "third party" as well as the target, and the test passed while proving nothing. Host-only matching conflates every service on one address. Rules take ports now.

Refusals get audited the same as requests. The refusals are the half that shows the engagement was respected.

## Recon writes a map, not a transcript

Recon walks the in-scope surface and records what it finds into a world model: endpoints keyed by method + host + path, the parameter *names* each one takes, the status codes it returned, and every form with its resolved action and input fields. Two hits on `/users?id=1` and `/users?id=2` collapse into one endpoint that takes `id` — because a planner wants "there is a `/users` endpoint that takes `id`", not two rows it has to re-derive.

It cannot leave scope and it is bounded. Every request goes through the egress client, and links are pre-filtered against scope before they're queued, so an out-of-scope link is dropped without a request. `MaxPages` and `MaxDepth` are hard stops — a crawler with no limit is a denial-of-service against your own target.

```
$ warrant recon examples/local.scope.json http://127.0.0.1:8099/
ENDPOINTS
  GET  http://127.0.0.1/            [200x1]
  GET  http://127.0.0.1/about.html  [200x1]
  GET  http://127.0.0.1/search  ?page,q  [404x1]
  GET  http://127.0.0.1/users   ?id     [404x1]

FORMS
  POST http://127.0.0.1:8099/login   (password, username)
```

HTML is extracted with regexes, not a full DOM parser — a deliberate trade to stay dependency-free (standard library only). It finds hrefs, form actions and input names well enough to seed a planner, and it will miss links built by JavaScript. That limit is stated, not hidden: a recon pass is a starting map, not ground truth.

## The planner proposes; it does not act

`warrant plan` runs recon and then reads the world model into a ranked list of probes. It only proposes — nothing is sent — so the plan is something you read top to bottom and approve before an executor (next) runs it one action at a time under the scope gate.

The catalog is fixed and typed. Actions come from a known set of check kinds, not free text, so whatever proposes them — these rules today, an LLM later — the executor still only ever runs a probe it understands. That is what would make an LLM safe to add here: it could rank and suggest, but not invent an action outside the catalog.

The rules lean on what has actually paid — unauthenticated reach into sensitive functions, and identifier tampering — and rank those first:

```
$ warrant plan examples/local.scope.json http://127.0.0.1:8099/
PLAN (highest priority first; nothing has been executed)
  [ 90] missing-auth   GET  .../admin/users?id=42
        path "/admin/users" looks sensitive; re-request with no credentials and compare  (safe)
  [ 80] param-tamper   GET  .../account/?account_id=1000
        mutate account_id: 1001 -> 1000 (adjacent object)  (safe)
  [ 30] method-probe   OPTIONS .../search?q=test   (safe)
  [ 50] method-probe   POST .../login
        authentication form; handle credentials via the operator, never auto-fill  (NEEDS-CONFIRM)
```

Each action is marked `safe` or `NEEDS-CONFIRM`: a read-only GET probe is safe, submitting a form or a state-changing verb is not, and the executor will have to require confirmation for the latter. A probe is only proposed against an endpoint that actually answered — tampering an id on something that only ever 404'd proves nothing.

## The executor runs the plan; the ledger refuses to overclaim

`warrant run` closes the loop: recon builds the map, the planner ranks the probes, and the executor runs the safe ones through the scope-gated client and turns each response into typed claims that the evidence ledger judges. Its job is not to decide what is a finding — it gathers what it honestly observed, with a control and repeated reproductions, and hands a Finding to the ledger.

Point it at an app riddled with textbook IDOR and it engages every one of them — and files none of them:

```
$ warrant run examples/vuln.scope.json http://127.0.0.1:8099/
  probe param-tamper  .../admin/users?id=41   -> not reportable
        blocked: primitive operates on a victim-scoped identifier, but no observed
                 claim shows where an attacker obtains that identifier from an
                 internet position; find the disclosure and make that the finding
  probe missing-auth  .../account?account_id=1001 -> not reportable
        blocked: claim P1 has no negative control, so 'the target does this for
                 everyone' is not ruled out
  probe method-probe  .../search?q=x
        allowed methods: GET, OPTIONS

summary: 9 executed, 0 skipped | findings: 0 reportable, 4 refused by the ledger
```

The executor found real distinct objects behind those ids — it isn't missing the bug. It refuses to *file* the bug because it never proved the object belongs to someone else. That is the entire project in one line of output: an agent that probes real vulnerabilities and still writes zero reports it can't stand behind. A NEEDS-CONFIRM action (a form submission, a state-changing verb) is skipped under the default policy, not run.

The measurement is baked in as a test (`internal/agent`): the pipeline runs against an app with a known bug list, and asserts it engages the IDOR/unauth surface while the ledger clears **zero** unprovable findings — precision 1.0, no false-positive reports — and never leaves scope.

## Use

```
warrant scope  <scope.json> <method> <url>   is this in scope, and why
warrant fetch  <scope.json> <method> <url>   request it, checking every redirect hop
warrant review <finding.json>                apply the evidence policy
warrant recon  <scope.json> <seed-url>       crawl in scope, map endpoints & forms
warrant plan   <scope.json> <seed-url>       recon, then propose ranked probe actions
warrant run    <scope.json> <seed-url>       recon, plan, run SAFE probes, judge findings
```

`scope` and `review` exit 3 when the answer is no, which is different from exiting 1 because something broke.

## Intended targets

Intentionally vulnerable applications I run myself (OWASP Juice Shop, DVWA), and programs that have authorized testing in writing. The scope file is the mechanism for the second case and the `authority` field is not decorative.

## Where it stands, and what's honest about it

The loop is closed and tested end to end: scope → egress → recon → world model → planner → executor → evidence, with the whole thing runnable as `warrant run` and measured by an integration test.

What it is: a scope-safe agent that maps a target, decides what to try, runs the read-only probes, and only files what it can prove. What it is not, yet, and I'd rather say so than imply otherwise:

- The probe catalog is small — IDOR, missing-auth, method and header checks. It's the shape that has paid, not the whole surface.
- The planner's rules are hand-written. The typed catalog is exactly what would let an LLM rank and propose here later without being able to invent an action the executor doesn't understand — but that swap isn't done.
- Reachability is the thing the executor can't establish alone (a second account, an id-disclosure), which is why honest IDOR findings come back refused. Closing that gap — chaining a disclosure into a reachability claim — is the natural next capability.
- HTML recon is regex-based and misses JS-built links.

Every one of those is a stated limit, not a hidden one, which is the same standard the ledger holds a finding to.
