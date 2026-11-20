# SECURITY.md — SurfaceMap

## Secrets

Optional API keys (Shodan, Censys, …) live in `.env` only (gitignored), loaded
through pydantic-settings. `.env.example` ships with empty values. Keys are
never logged, cached, or rendered into reports.

## Auth boundaries

No user auth (local CLI). The authorization boundary is `scope.yaml`
(gitignored): the tool refuses any domain not listed there, with exact suffix
matching (`evil-example.com` does not match `example.com`).

## Sensitive data / PII

No personal data collected: WHOIS/RDAP contacts dropped (only registrar, dates,
nameservers kept), certificate SANs containing `@` discarded, Wayback URLs
stripped of query strings. Cache (`.cache/`) and outputs (`out/`) are gitignored.

## Pre-release checklist

- `git log -p` / secret scan: no key, no `.env`, no `scope.yaml` committed.
- Test fixtures anonymized (no real personal data in recorded responses).
- README demo uses `logan-villard.fr` (owned) or a fictional domain only.
