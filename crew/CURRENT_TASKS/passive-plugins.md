# passive-plugins

Phase 3: passive data-source plugins, all tested with mocked fixtures (respx). One commit per plugin.

Decision validated by the user: `normalize_domain` in scope.py stays strict (rejects `_`); technical labels like `_dmarc`/`_domainkey` are only built inside the DNS plugin from an already-validated domain.
Each plugin's module docstring states exactly what traffic it emits (never to the target itself).

Branch: `feat/passive-plugins`
Batch: C
Zone: `src/surfacemap/plugins/`, `tests/fixtures/`, `tests/`
Depends on: collection-engine.md

Rules: Conventional Commits, one atomic commit per action below, TDD (test first), passive only, scope first, tests fully mocked (respx), coverage >= 80 %.

## Actions

- [ ] feat(plugins): crtsh
- [ ] feat(plugins): dns records (A/AAAA/CNAME/MX/TXT/NS); `_dmarc`/`_domainkey` built only here from a validated domain
- [ ] feat(plugins): spf/dmarc parsing
- [ ] feat(plugins): rdap (contacts dropped via privacy filters)
- [ ] feat(plugins): whois fallback
- [ ] feat(plugins): asn via Team Cymru DNS
- [ ] feat(plugins): geoip (offline dataset, iptoasn/GeoLite2 - note licence)
- [ ] feat(plugins): wayback CDX (no query strings kept)
- [ ] feat(plugins): shodan (read-only, API key optional)
- [ ] feat(plugins): censys (read-only, API key optional)
- [ ] feat(plugins): dorks generator (reuse/optional dependency on sibling project dorkint; never executes searches)
- [ ] docs(plugins): verify each module docstring states the traffic it emits
- [ ] Review + merge branch into main
