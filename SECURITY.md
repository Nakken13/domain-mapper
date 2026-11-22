# SECURITY.md — domain-mapper

## Secrets

Optional API keys (Shodan, Censys, …) live in `.env` only (gitignored), loaded
through pydantic-settings. `.env.example` ships with empty values. Keys are
never logged, cached, or rendered into reports.

## Auth boundaries

No user auth (local CLI). Authorization is self-declared by running the scan: the tool is passive
(no traffic to the target) and cannot verify ownership. By default the crawl is bounded to the
scanned domain and its subdomains, with exact suffix matching (`evil-example.com` does not match
`example.com`). An optional `--scope-file` (`scope.yaml`, gitignored) adds an allow-list with
expiry dates for teams/CI.

## Sensitive data / PII

No personal data collected: WHOIS/RDAP contacts dropped (only registrar, dates,
nameservers kept), certificate SANs containing `@` discarded, Wayback URLs
stripped of query strings. Cache (`.cache/`) and outputs (`out/`) are gitignored.

## Pre-release checklist

- `git log -p` / secret scan: no key, no `.env`, no `scope.yaml` committed.
- Test fixtures anonymized (no real personal data in recorded responses).
- README demo uses `logan-villard.fr` (owned) or a fictional domain only.
