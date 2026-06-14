# Contributing

Contributions that improve safe, authorized OAST discovery, reliability, portability, documentation, or evidence quality are welcome.

## Before opening a pull request

1. Create an issue for large behavioral changes.
2. Keep default behavior conservative and non-destructive.
3. Add tests for mutation, parsing, correlation, and output changes.
4. Run `make check`.
5. Update documentation and `CHANGELOG.md` when user-visible behavior changes.

## Development

```bash
git clone https://github.com/pingback-sh/pbscan.git
cd pbscan
make check
```

The project uses only the Go standard library. New dependencies need a clear maintenance, security, and licensing justification.

## Payload contributions

Pull requests must not add payloads intended to read local files, retrieve cloud metadata, access internal administrative services, tunnel arbitrary protocols, evade authorization controls, or cause disruption. Safe callback encodings and parser-compatibility improvements are acceptable when documented and tested.

## Tests

- Unit tests belong next to the package they cover.
- Network tests must use `httptest` or a loopback-only test server.
- Tests must not contact public services.
- Test fixtures must not contain real credentials or customer data.

## Commit and pull-request notes

Explain the problem, the chosen design, safety implications, compatibility impact, and the commands used to test the change.
