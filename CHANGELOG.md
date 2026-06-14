# Changelog

All notable changes will be documented here.

## 1.1.0 - 2026-06-14

### Added

- One-time `pbscan auth` setup using a revocable PingBack Pro API token.
- Automatic listener creation for every scan.
- Automatic `/injections.php` registration and use of API-returned HTTP payloads.
- Native `/hits.php` polling with `listener_id`, pagination, `since_id`, and `correlation_id` matching.
- Positional file/URL inputs and zero-argument stdin scanning.
- Persistent delayed-hit cursor and API-aware `watch` mode.
- Default redaction of sensitive headers in remote responsible-request evidence.
- Automatic cleanup of a newly created listener when pre-dispatch registration fails.
- API client and end-to-end workflow tests using local `httptest` servers.

### Changed

- The default workflow no longer requires `--listener`, `--feed-url`, or listener dashboard tokens.
- Authorized-use acceptance can be saved during one-time authentication.
- Default maximum attempts is 500 to leave room under the documented default API request allowance.
- Session schema upgraded to version 2 while retaining legacy JSON compatibility.
- Manual listener/feed operation moved to explicit legacy compatibility mode.

## 1.0.0 - 2026-06-14

### Added

- Correlated query, JSON, form, and optional header mutation.
- Raw HTTP request, URL list, repeated URL, and stdin input modes.
- Pingback listener callback templates and schema-independent JSON feed matching.
- Concurrent dispatch, global rate limiting, retries, timeouts, and redirect control.
- Multiple callback observations per finding.
- Atomic resumable sessions and delayed callback watching.
- JSONL evidence, chronological activity log, and JSON summary.
- Authorization and private-target safety controls.
- CI, release automation, Docker build, local lab, and project documentation.
