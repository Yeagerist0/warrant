# warrant

An autonomous web-application testing agent that can't act outside its authorization and can't report what it didn't demonstrate.

Both halves are enforced in code, not in a prompt. That's the whole idea: an agent that plans its own actions will eventually plan one nobody authorized, and it will always be able to write a confident paragraph about a bug it never proved.

## Status

The enforcement spine is built and tested — scope, egress, evidence. The planner and the executor that sit on top of it are not written yet. I'm building it in this order on purpose, because the parts that say *no* are the parts that have to be right before anything starts acting on its own.

26 tests, `go test ./...`.

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

## Use

```
warrant scope  <scope.json> <method> <url>   is this in scope, and why
warrant fetch  <scope.json> <method> <url>   request it, checking every redirect hop
warrant review <finding.json>                apply the evidence policy
```

`scope` and `review` exit 3 when the answer is no, which is different from exiting 1 because something broke.

## Intended targets

Intentionally vulnerable applications I run myself (OWASP Juice Shop, DVWA), and programs that have authorized testing in writing. The scope file is the mechanism for the second case and the `authority` field is not decorative.

## Next

Recon and a world model, then the planner, then an executor limited to a fixed tool allowlist — no arbitrary shell, since an LLM proposing structured actions against a typed model is both safer and easier to replay than one proposing commands. Then the measurement that interests me most: against a target with a known bug list, what's the false-positive rate, and how much of it does the ledger catch before it reaches a report?
