# risk-rules

Phase 4: risk rule engine and rules (all passive: no HTTP request to the target).

Branch: `feat/risk-rules`
Batch: D
Zone: `src/surfacemap/risk/`, `tests/`
Depends on: passive-plugins.md

Rules: Conventional Commits, one atomic commit per action below, TDD (test first), passive only, scope first, tests fully mocked (respx), coverage >= 80 %.

## Actions

- [ ] feat(risk): rule engine
- [ ] feat(risk): takeover rule (PASSIVE only: CNAME to a known risky provider listed in `src/surfacemap/risk/data/takeover_providers.yaml` + NXDOMAIN on the CNAME target, no HTTP fingerprint)
- [ ] feat(risk): missing/weak DMARC and SPF rule
- [ ] feat(risk): expired / soon-expiring certificates rule
- [ ] feat(risk): exposed dev/staging/test subdomains rule
- [ ] feat(risk): multiple hosting providers rule
- [ ] Review + merge branch into main
