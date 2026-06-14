# Security policy

## Supported versions

Security fixes are applied to the latest tagged release and the `main` branch.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose users, API credentials, callback data, or target request material.

Send a private report to the security contact published by Pingback.sh. Include:

- affected version or commit;
- operating system and installation method;
- reproduction steps using a local test target;
- expected and observed behavior;
- impact and suggested remediation, when known.

Remove production tokens, cookies, authorization headers, private URLs, and callback contents from the report. Acknowledgement and remediation timing depend on severity and reproducibility.

## Secrets

The revocable PingBack API token is stored in the local configuration file with mode `0600` or supplied through `PINGBACK_API_TOKEN`. It is not written to scan sessions or reports. Keep configuration and output directories private, avoid committing them, use one token per environment, and revoke any token that is accidentally disclosed.

Raw request files and local attempt/session files may contain target cookies, authorization headers, URLs, and bodies. Remote correlation evidence redacts common credential headers by default; `--include-request-secrets` is an explicit opt-in.
