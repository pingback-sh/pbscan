# CLI reference

## Root shortcuts

All of these start a scan:

```bash
pbscan urls.txt
pbscan -l urls.txt
pbscan 'https://target.example/fetch?url=x'
cat urls.txt | pbscan
```

`pbscan scan ...` remains available for explicit scripts.

## `pbscan auth`

Stores and validates a revocable PingBack Pro API token.

```bash
pbscan auth --token pba_xxx --accept-authorized-use
```

Options:

| Option | Purpose |
|---|---|
| `--token` | Revocable API token. |
| `--token-stdin` | Read the token from stdin. |
| `--api-base` | API base URL; defaults to `https://pingback.sh/api/v1`. |
| `--accept-authorized-use` | One-time acceptance that every target must be authorized. |

## `pbscan scan`

### Input

| Option | Purpose |
|---|---|
| `-u`, `--url` | Target URL; repeatable. |
| `-l`, `--list` | URL-list file. |
| `--stdin` | Read URLs from stdin. |
| `--request` | Raw HTTP request file. |
| `--base-url` | Base for a relative raw request target. |

Positional absolute URLs and readable files are accepted.

### Automatic PingBack API

| Option | Purpose |
|---|---|
| `--api-base` | Override API base URL. |
| `--api-token` | Override saved/environment token for this process. |
| `--label` | Listener label. |
| `--include-request-secrets` | Do not redact sensitive headers in remote correlation evidence. |

### Mutation

| Option | Purpose |
|---|---|
| `--no-query` | Disable query mutation. |
| `--no-body` | Disable JSON/form mutation. |
| `--headers` | Enable conservative header mutation. |
| `--header NAME` | Add a header; repeatable. |

### Transport and limits

| Option | Default | Purpose |
|---|---:|---|
| `--threads` | 10 | Concurrent target workers. |
| `--rate` | 10 | Target requests per second. |
| `--timeout` | 12s | Target request timeout. |
| `--retries` | 1 | Network retries. |
| `--wait` | 20s | Post-dispatch polling period. |
| `--max-attempts` | 500 | Correlated record/API budget ceiling. |
| `--follow-redirects` | false | Follow target redirects. |
| `--insecure` | false | Skip target certificate validation. |
| `--allow-private-targets` | false | Permit loopback/private targets for authorized labs. |

### Output and automation

| Option | Purpose |
|---|---|
| `--output` | Output root. |
| `--dry-run` | No API or target traffic. |
| `--json` | JSON-line terminal events. |
| `--silent` | Suppress progress. |
| `--fail-on-findings` | Non-zero exit after confirmed callbacks. |
| `--authorized` | Per-run authorization override when not saved during auth. |

### Legacy mode

| Option | Purpose |
|---|---|
| `--legacy` | Force manual OAST mode. |
| `--listener` | Manual listener host/URL. |
| `--callback-template` | Manual callback template containing `{token}`. |
| `--feed-url` | Generic JSON feed. |
| `--feed-header` | Generic feed header; repeatable. |

## `pbscan watch`

```bash
pbscan watch output/pbs-xxxx/session.json
```

Options:

| Option | Default | Purpose |
|---|---:|---|
| `--session` | — | Alternative named session path. |
| `--duration` | 10m | Watch duration. |
| `--interval` | 2s | Poll interval. |
| `--api-token` | saved token | Process-only token override. |
| `--json` | false | JSON-line events. |
| `--silent` | false | Suppress output. |

## `pbscan doctor`

Validates the saved PingBack API token and API base URL.

```bash
pbscan doctor
```

## `pbscan logout`

Removes the token from local configuration without revoking it server-side.

```bash
pbscan logout
```
