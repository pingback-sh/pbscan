# Threat model

## Assets

- revocable PingBack API token;
- target authorization headers and cookies;
- target URLs and request bodies;
- callback evidence;
- listener and correlation metadata.

## Authorization misuse

A scanner can be pointed outside an operator's permission. During one-time `pbscan auth`, the operator must accept authorized-use conditions. Non-persistent and CI usage can instead pass `--authorized` or set `PBSCAN_AUTHORIZED=1`. This is an accountability measure, not technical proof of authorization.

## Token exposure

The token is stored in a local `0600` configuration file or supplied by environment variable. It is not written to session files, reports, target requests, terminal progress, or callback payloads. Users should create a dedicated revocable token for each environment.

## Sensitive responsible requests

PingBack correlation records can contain request evidence. pbscan redacts common credential headers from the remote copy by default. The exact target request remains in protected local files. `--include-request-secrets` is an explicit opt-in.

## Target-side risk

Defaults are intentionally conservative:

- private/loopback targets blocked unless explicitly enabled;
- no redirect following;
- TLS verification enabled;
- bounded workers and rate;
- finite response reads;
- query/form/JSON string mutation only;
- no file, metadata, alternate-protocol, or destructive payload packs.

## API-side risk

A large scan can consume the account API allowance and create many listener/injection records. API mode defaults to 500 attempts, registers before dispatch, handles HTTP 429, and attempts cleanup if registration fails before any target traffic is sent.

## Delayed evidence

Listeners remain active after dispatch so delayed callbacks are not lost. Operators should archive or delete listeners from PingBack when their authorized engagement ends and retain evidence according to applicable program rules.
