# Output format

## `attempts.jsonl`

One registered mutation per line:

```json
{
  "id": "pba-local-00001-random",
  "scan_id": "pbs-example",
  "original_target_url": "https://target.example/fetch?url=original",
  "target_url": "https://target.example/fetch?url=https%3A%2F%2Flistener.pingback.sh%2Fcb%3Fcid%3Dinj-example",
  "vector": "query",
  "injection_point": "url",
  "callback_url": "https://listener.pingback.sh/cb?cid=inj-example",
  "correlation_id": "inj-example",
  "payloads": {
    "http": "https://listener.pingback.sh/cb?cid=inj-example",
    "dns": "inj-example.listener.pingback.sh"
  }
}
```

## `results.jsonl`

One target dispatch result per line. HTTP status codes show delivery behavior only and are not confirmations.

## `findings.jsonl`

A finding is emitted only after PingBack returns a matching correlation ID. Repeated DNS/HTTP events for the same attempt are preserved as observations.

## `session.json`

Resumable state includes:

- session version and mode;
- listener ID/host;
- API base URL but not token;
- last processed hit ID;
- attempts, dispatch results, and findings.

## `summary.json`

Contains counts, callback event totals, vectors, and finding IDs.
