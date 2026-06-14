# Architecture

## Components

- `internal/input`: URL lists and raw HTTP requests.
- `internal/target`: target-policy checks.
- `internal/mutate`: one-input-at-a-time query, form, JSON, and header mutations.
- `internal/pingback`: API v1 client and paginated hit watcher.
- `internal/scanner`: bounded target dispatcher.
- `internal/session`: atomic resumable state.
- `internal/report`: JSONL evidence and summary output.
- `internal/callback`: legacy callback-template/feed support.
- `internal/app`: CLI orchestration.

## Automatic API-mode lifecycle

```text
parse input
  │
  ▼
build placeholder mutations
  │
  ▼
create PingBack listener
  │
  ▼
register every injection
  │       └── correlation_id + protocol payloads
  ▼
replace placeholder with returned HTTP payload
  │
  ├────────► start hits watcher
  │
  ▼
dispatch target requests
  │
  ▼
correlate hit.correlation_id to attempt.correlation_id
  │
  ▼
atomic session + reports
```

Target traffic is not sent until all API correlation records have been created. This guarantees that an immediate callback cannot arrive before its responsible request metadata exists.

## Identity model

Each attempt has two identifiers:

- a local immutable `pba-*` ID used for files, logs, and target request headers;
- the PingBack `inj-*` correlation ID returned by `/injections.php`.

The scanner never assumes that these identifiers have the same format.

## Persistence

The session contains API metadata and correlation IDs but never the API token. Writes are performed through a temporary file followed by atomic rename. Results are batched, while findings are flushed immediately.

## Compatibility

Session version 2 adds API mode, listener metadata, correlation IDs, payload maps, and hit cursors. Version 1 legacy sessions can still be loaded because new JSON fields are optional.
