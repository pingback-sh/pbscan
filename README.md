# pbscan

`pbscan` is an automatic, correlated SSRF/OAST scanner for **authorized security testing**. It uses the PingBack.sh API v1 to create a listener, register every injection attempt, obtain the official protocol payload, poll captured evidence, and map each callback back to the exact parameter, body field, or header that caused it.

The normal workflow does **not** require a listener hostname, listener dashboard token, callback template, or feed URL.

> Use pbscan only against systems you own or are explicitly authorized to test. The project does not include cloud-metadata extraction, local-file payload packs, `gopher://`, `dict://`, destructive probes, or exploitation automation.

## 30-second setup

Create a revocable Pro API token in **PingBack.sh → My listeners**, then configure it once:

```bash
pbscan auth --token pba_your_revocable_token --accept-authorized-use
```

After that, a scan only needs an input file:

```bash
pbscan urls.txt
```

Equivalent forms:

```bash
pbscan -l urls.txt
cat urls.txt | pbscan
pbscan 'https://target.example/fetch?url=https://example.org'
```

## What happens automatically

For every scan, pbscan:

1. validates and parses the supplied URLs or raw request;
2. creates a dedicated reusable PingBack listener;
3. creates one correlated injection record per mutation through `/api/v1/injections.php`;
4. replaces the selected input with the returned `payloads.http` value;
5. dispatches the target requests with concurrency and rate limits;
6. polls `/api/v1/hits.php` using `listener_id`, `since_id`, and pagination;
7. matches each hit by `correlation_id`;
8. saves resumable sessions, evidence, findings, and summaries locally.

```text
urls.txt
   │
   ▼
mutation engine
   │
   ├── create listener ─────────────► PingBack API v1
   │
   ├── register exact attempt ──────► correlation_id + HTTP/DNS/SMTP/XSS payloads
   │
   ├── send returned HTTP payload ──► authorized target
   │
   └── poll hits.php ◄────────────── DNS / HTTP / HTTPS callback evidence
                    │
                    ▼
          exact parameter + request + evidence
```

## Features

- Automatic PingBack listener creation per scan.
- Automatic correlation through PingBack API v1.
- Query-string mutation, including repeated parameters.
- Nested JSON string-field mutation using JSON Pointer paths.
- `application/x-www-form-urlencoded` mutation.
- Optional conservative routing/header checks.
- Raw HTTP request import with cookies and authorization preserved locally.
- Sensitive headers redacted from remote correlation records by default.
- URL file, positional URL, repeated `-u`, and stdin pipeline support.
- Concurrent target workers, rate limiting, retries, timeouts, redirect control, and TLS controls.
- Multiple callback events retained for one injection, such as DNS followed by HTTPS.
- Atomic resumable sessions and delayed callback monitoring.
- JSONL evidence, chronological activity log, and machine-readable summary.
- Legacy listener/feed mode for non-PingBack or older deployments.
- No third-party Go dependencies.

## Installation

### Prebuilt binary

Download the binary for Linux, Windows, or macOS from the GitHub release and place it in your `PATH`.

### Go install

```bash
go install github.com/pingback-sh/pbscan/cmd/pbscan@latest
```

### Build from source

```bash
git clone https://github.com/pingback-sh/pbscan.git
cd pbscan
go build -o pbscan ./cmd/pbscan
```

## Authentication

The API token is stored in:

```text
~/.config/pbscan/config.json
```

The configuration directory is created with mode `0700` and the file with mode `0600`.

Validate the saved connection:

```bash
pbscan doctor
```

Remove the locally stored token:

```bash
pbscan logout
```

Environment-variable mode is also supported:

```bash
export PINGBACK_API_TOKEN='pba_your_token'
export PBSCAN_AUTHORIZED=1
pbscan urls.txt
```

`PBSCAN_CONFIG` can point to a different configuration file.

## Input modes

### File

```bash
pbscan urls.txt
```

Blank lines and lines beginning with `#` are ignored.

### One or more URLs

```bash
pbscan \
  -u 'https://one.example/fetch?url=x' \
  -u 'https://two.example/proxy?destination=x'
```

A single URL can be positional:

```bash
pbscan 'https://target.example/fetch?url=x'
```

### Stdin

```bash
cat urls.txt | pbscan
```

Authorized recon pipeline:

```bash
katana -u https://target.example -silent \
  | gf ssrf \
  | pbscan
```

### Raw HTTP request

```bash
pbscan --request request.txt
```

For a relative request target without a usable `Host` header:

```bash
pbscan --request request.txt --base-url https://target.example
```

## Mutation coverage

### Query parameters

```text
GET /fetch?url=one&id=two
```

Produces one correlated attempt for `url` and another for `id`. Repeated keys are represented as `key[0]`, `key[1]`, and so on.

### JSON bodies

```json
{
  "image": {"url": "https://example.org/image.png"},
  "webhooks": ["https://example.org/hook"]
}
```

Produces points such as:

```text
/image/url
/webhooks/0
```

Only JSON string values are mutated.

### Form bodies

```text
url=https%3A%2F%2Fexample.org&name=test
```

Each form value is tested independently.

### Headers

Header checks are opt-in:

```bash
pbscan urls.txt --headers
```

Default conservative list:

```text
Referer
Origin
X-Forwarded-Host
X-Original-URL
X-Rewrite-URL
Forwarded
Base-URL
```

Add an explicit header:

```bash
pbscan urls.txt --headers --header X-Custom-Callback
```

`Host` and `Content-Length` are never mutated by the header engine.

## Common options

```text
--label TEXT              custom label for the automatically created listener
--threads 10              concurrent target workers, maximum 100
--rate 10                 target requests per second
--timeout 12s             target request timeout
--retries 1               network retries, maximum 5
--wait 20s                continue polling after dispatch
--follow-redirects        follow target redirects
--insecure                skip target TLS certificate validation
--headers                 enable header mutation
--header NAME             add a header mutation, repeatable
--no-query                disable query mutation
--no-body                 disable JSON/form mutation
--max-attempts 500        safety/API-budget limit; 0 disables it
--dry-run                 build local attempts without API or target requests
--include-request-secrets include Cookie/Authorization in PingBack correlation evidence
--json                    JSON-line terminal events
--silent                  suppress progress output
--fail-on-findings        return a non-zero exit code after confirmed callbacks
```

The default `500`-attempt ceiling leaves room beneath PingBack's documented default API allowance for listener creation and hit polling. Split larger jobs or deliberately raise the limit when your API quota permits it.

## Request evidence and secrets

Before dispatch, pbscan registers a responsible request containing a stable marker at the tested location:

```text
{{PINGBACK_HTTP_PAYLOAD}}
```

By default, these headers are redacted in the copy sent to PingBack:

```text
Authorization
Proxy-Authorization
Cookie
Set-Cookie
X-API-Key
API-Key
```

The real values remain available only in the local attempt/session files. Use `--include-request-secrets` only when you intentionally want those values stored with the remote correlation record.

## Output

Each scan creates:

```text
output/pbs-<scan-id>/
├── activity.log
├── attempts.jsonl
├── results.jsonl
├── findings.jsonl
├── summary.json
└── session.json
```

An attempt includes both the local ID and PingBack correlation ID:

```json
{
  "id": "pba-local-scan-00001-random",
  "correlation_id": "inj-a1b2c3",
  "vector": "query",
  "injection_point": "url",
  "callback_url": "https://listener.pingback.sh/cb?cid=inj-a1b2c3"
}
```

A `200 OK` target response is not a finding. A finding is confirmed only after a matching hit is returned by PingBack with the expected `correlation_id`.

## Delayed callbacks

The listener and correlation records remain in PingBack after the target requests finish. Resume polling later with:

```bash
pbscan watch output/pbs-xxxx/session.json
```

Custom duration:

```bash
pbscan watch output/pbs-xxxx/session.json --duration 24h --interval 5s
```

The session stores the last processed hit ID and resumes with `since_id` instead of downloading the full history.

## Legacy mode

Manual listener/feed configuration remains available for older deployments and generic OAST services:

```bash
pbscan urls.txt \
  --legacy \
  --listener https://abc12345.pingback.sh \
  --feed-url 'https://legacy.example/feed'
```

This is not the recommended PingBack.sh workflow. API v1 mode is selected automatically whenever a saved API token exists and no legacy flags are supplied.

## Local tests

```bash
go test ./...
go test -race ./...
go vet ./...
```

Build all supported platforms:

```bash
make cross
```

## Security and contribution

Read [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before contributing scanner behavior or payloads.

## License

MIT
