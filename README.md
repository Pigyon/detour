<div align="center">
  <h1>detour</h1>
  <img src="readme/detour.png" width="200" alt="detour logo">
  <h3><i>Every redirect goes somewhere</i></h3>
  <p>Open redirect discovery and verification engine</p>

[![Go](https://img.shields.io/badge/Go-1.26-233246?logo=go&logoColor=00ADD8)](https://go.dev)
[![Static](https://img.shields.io/badge/build-static_CGO__ENABLED%3D0-2E7B7E)](#)
[![Techniques](https://img.shields.io/badge/techniques-44-1F2937)](REFERENCE.md)
[![SARIF](https://img.shields.io/badge/output-SARIF_2.1.0-065F46)](#)

</div>

---

## What is it?

A single Go binary that finds open redirects and proves them.

It reads destinations a parameter scanner cannot: ones buried in compressed or
signed envelopes, ones guarded by minified client-side JavaScript, and ones that
only fire after the page loads. Findings record what the redirect can do (OAuth
`redirect_uri` theft, `javascript:` execution, Referer leak, CSP bypass, cache
poisoning) and CVSS is derived from that.

## How it works?

```
surface -> harvest -> select -> [ attack + decode + js ] -> confirm -> report
```

| Stage | What it does |
| --- | --- |
| `surface` | Enumerate subdomains, resolve them, probe what answers, flag vendor-delegated hosts |
| `harvest` | Pull URLs from web archives, the target's own files, and a crawl, keeping only what belongs to the target |
| `select` | Normalize, dedupe, and classify every URL into injection points |
| `attack` | Send the redirect destination per technique and read Location, meta refresh, Refresh, and CRLF |
| `decode` | Peel opaque state (base64, base32, hex, zlib, gzip, deflate, brotli, JWT, JSON, form) until a URL falls out, then rewrite it and replay |
| `js` | Parse client-side code for navigation sinks, resolve the guards protecting them, and build a payload per guard kind |
| `confirm` | Drive headless Chrome, intercept the navigation before it leaves, capture a screenshot and HAR |
| `report` | Dedupe by root cause, write a submittable report per finding, emit JSONL, JSON and SARIF |

`decode` and `js` are both standalone commands and stages the attack engine calls
into: a blob field found by `decode` is attacked like any other parameter, and a
sink found by `js` is confirmed in the browser.

Two details matter in practice:

**Envelopes get two mutations.** Rewriting only the destination is the strongest
proof, so it is tried first. When a wrapper binds the destination to a
per-message value and rejects the swap, detour rebuilds the envelope with the
per-message fields zeroed to inert values of the same shape. The finding says
which one worked.

**The destination is never contacted.** Payloads aim at `--redirect-to`
(`https://google.com` by default), and the scope guard refuses that host and
everything under it, so a confirmed redirect is proven by the response rather
than by traffic to a server you control.

**`--passive` means passive.** It runs archives, imports and client-side reading only.
No payload is sent, so an endpoint is never touched during a window you are not
cleared for.

**Output is a report, not a score.** Every run writes `REPORT.md` covering the
whole run, grouped by endpoint, plus one directory per finding holding a
`REPORT.md` you can submit as written: what it is, the exact request, the
response, why the validator let it through, and the fix.

**A finding needs two destinations.** A target that always redirects somewhere
would otherwise look vulnerable, so every hit is re-probed with an independent
second destination and only reported when both are reflected. That second host
is refused by the guard too.

## Protected and authenticated targets

Many real redirect bugs live behind a login or a bot-defense WAF, so detour can
reach both.

**Authenticated scanning that outlasts a short session.** Point `--cookies-file`
(and `--headers-file`, for a bearer) at a live session. `--session-refresh`
re-reads them on an interval, optionally running `--creds-refresh-cmd` first to
re-mint them (for example by re-exporting a browser session), so a cookie or a
five-minute bearer does not silently expire mid-run. `--auth-check` probes an
authenticated-only URL to notice when the session dies; with
`--auth-check-required` a lost session stops the run instead of silently
continuing as anonymous and under-reporting.

**Browser TLS impersonation.** A WAF like Akamai or Cloudflare fingerprints the
TLS handshake, and Go's default handshake is an instant tell. `--tls-impersonate
chrome` (or `firefox`) replays that browser's TLS ClientHello and the headers to
match, so requests look like the browser they claim to be. The User-Agent is
operator-supplied via `--user-agent` (required here, so it matches the real
browser whose session you are using) rather than a constant that rots.

**Runs that do not get cut.** By default a run has no time limit. `--budget`
caps it and still reports everything proved so far when it expires;
`--budget-expand 30m,1h,2h` resumes under the next budget each time a round is
cut, carrying proved findings forward via the checkpoint, until a round finishes.

**Multiple apexes in one run.** Pass more than one target
(`detour a.com b.com c.com`) and the whole pipeline runs per apex into its own
`--out` subdirectory.

### Built on

Static build, no cgo, so the binary is one file with no runtime dependencies.

| Library | Used for |
| --- | --- |
| [`spf13/cobra`](https://github.com/spf13/cobra) + [`spf13/viper`](https://github.com/spf13/viper) | Commands and layered config (flag > env > file) |
| [`projectdiscovery/subfinder`](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration |
| [`projectdiscovery/dnsx`](https://github.com/projectdiscovery/dnsx) | Resolution and CNAME chains, which is how vendor delegation is spotted |
| [`projectdiscovery/httpx`](https://github.com/projectdiscovery/httpx) | Host probing and fingerprinting |
| [`projectdiscovery/retryablehttp-go`](https://github.com/projectdiscovery/retryablehttp-go) | HTTP client for the surface-stage recon tooling |
| [`refraction-networking/utls`](https://github.com/refraction-networking/utls) | Browser TLS ClientHello impersonation for `--tls-impersonate` |
| [`tdewolff/parse/v2`](https://github.com/tdewolff/parse) | Pure-Go JavaScript parser and AST, with scope-resolved variable links |
| [`chromedp/chromedp`](https://github.com/chromedp/chromedp) + [`cdproto`](https://github.com/chromedp/cdproto) | Headless Chrome over CDP, aborting each navigation at the Fetch domain |
| [`andybalholm/brotli`](https://github.com/andybalholm/brotli) | Brotli layer in the envelope decoder |
| [`golang.org/x/net`](https://pkg.go.dev/golang.org/x/net) | HTML tokenizing for meta refresh and inline script extraction |
| [`golang.org/x/sync`](https://pkg.go.dev/golang.org/x/sync) + [`golang.org/x/time`](https://pkg.go.dev/golang.org/x/time) | Bounded concurrency and per-host rate limiting |
| [`stretchr/testify`](https://github.com/stretchr/testify) | Tests |

The JS parser is `tdewolff/parse` rather than jsluice because jsluice reaches
tree-sitter through cgo, which would end the static build.

## Flags

Global, available on every command:

| Flag | Default | Description |
| --- | --- | --- |
| `--scope-file` | | Bug bounty scope list. A hard boundary on every request |
| `--redirect-to` | `https://google.com` | Destination payloads try to reach. A redirect arriving here is the finding. Never contacted. Accepts a URL or a bare host |
| `--canary` | | Deprecated name for `--redirect-to` |
| `--header` | | Extra request header, repeatable. In-scope hosts only |
| `--cookie` | | Inline session cookies. In-scope hosts only |
| `--cookies-file` | | Netscape cookie jar. In-scope hosts only |
| `--headers-file` | | File of `Name: Value` header lines, re-read on `--session-refresh`. Where a rotating bearer lives. In-scope hosts only |
| `--proxy` | | HTTP proxy URL, for example `http://127.0.0.1:8080` |
| `--tls-impersonate` | | Impersonate a browser's TLS fingerprint (`chrome`, `firefox`) and send matching browser headers, to get past WAF bot detection that fingerprints Go's default handshake. Requires `--user-agent` |
| `--user-agent` | | User-Agent sent on every request. Operator-supplied, not baked in. Required with `--tls-impersonate` so it matches the impersonated browser |
| `--session-refresh` | `0` | Re-read `--cookies-file` and `--headers-file` (running `--creds-refresh-cmd` first) on this interval, to keep a short-lived session fresh. `0` disables |
| `--creds-refresh-cmd` | | Command run at the start of each `--session-refresh` to mint fresh credentials into `--cookies-file` and `--headers-file` |
| `--auth-check` | | In-scope URL returning authenticated-only content. Probed to detect a lost session |
| `--auth-check-expect` | | Substring that must appear in `--auth-check`'s response while authenticated |
| `--auth-check-required` | `false` | Stop the run if the `--auth-check` probe shows the session is not authenticated |
| `--rate` | `5` | Per-host requests per second |
| `--concurrency` | `10` | Max concurrent in-flight requests |
| `--delay` | | Additional delay between per-host requests |
| `--timeout` | `10s` | Per-request timeout |
| `--budget` | `0` | Stop the whole run after this long and report what was proved so far. `0` means unlimited |
| `--budget-expand` | | Comma-separated budgets (for example `30m,1h,2h`): resume under the next each time a run is cut, until it finishes within one. Takes precedence over `--budget` |
| `--out` | | Write results to this directory |
| `--passive` | `false` | Archives and imports only. Never touch the target |
| `--crawl` | `true` | Crawl the target for URLs |
| `--js` | `true` | Read client-side code for navigation sinks |
| `--depth` | `3` | Crawl depth |
| `--deep` | `false` | Brute-force hidden redirect parameters on endpoints with no candidate |
| `--vendor-only` | `false` | Keep only known ESP and martech click wrappers |
| `--escalate` | `false` | Attach escalation capabilities. Never performs the escalation |
| `--headless` | `false` | Prove candidates in a headless browser (needs Chrome) |
| `--nuclei` | `false` | Also run an installed nuclei binary as a second opinion. Absent nuclei is a no-op |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--config` | `$HOME/.detour.yaml` | Config file. Precedence is flag > env > file |

Per-command:

| Command | Flag | Description |
| --- | --- | --- |
| `attack` | `--filter` | Comma-separated mechanisms to report (`blob`, `crlf`, `header`, `host`, `hpp`, `js`, `meta`, `nuclei`, `path`, `query`, `refresh`) |
| `attack` | `--keyword` | Injection mark replaced by each payload (default `FUZZ`) |
| `attack` | `--resume` | Append-only checkpoint file. Skip completed attempts |
| `decode` | `--matrix` | Replay the envelope with each field flipped to record what the server validates |
| `js` | `--dns` | Resolve every allowlisted host and flag the ones that do not exist |
| `js` | `--findings` | Emit findings as JSONL instead of the full analysis |
| `confirm` | `-l`, `--list` | `findings.jsonl` to confirm, or `-` for stdin |
| `confirm` | `--referer-test` | Run the referer redirect test against this URL instead |
| `dorks` | `--raw` | Print bare queries, one per line |
| `lab` | `--addr` | Listen address (default `:1337`) |
| `lab` | `--list` | Print endpoints as JSON and exit |
