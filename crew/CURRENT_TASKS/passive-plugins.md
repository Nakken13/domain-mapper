# passive-plugins

Phase 3: passive data-source plugins, all tested with mocked fixtures (respx). One commit per plugin.

Decision validated by the user: `normalize_domain` in scope.py stays strict (rejects `_`); technical labels like `_dmarc`/`_domainkey` are only built inside the DNS plugin from an already-validated domain.
Each plugin's module docstring states exactly what traffic it emits (never to the target itself).

Branch: `feat/passive-plugins`
Batch: C
Zone: `src/surfacemap/plugins/`, `tests/fixtures/`, `tests/`
Depends on: collection-engine.md

Decisions 2026-11-21 (user, after `architect` + `legal`):
- Pre-cache redaction: `HttpClient.get_text(redact=...)` (out-of-zone edit in `collect/http.py`, approved). Raw bodies with personal data (RDAP vCards, crt.sh emails, PEM DER) never reach the SQLite cache.
- `dnspython` added to `pyproject.toml` (approved out-of-zone edit); DNS behind an injected resolver, fake in tests ("respx" read as "offline"). WHOIS fallback = stdlib port-43 socket, no python-whois.
- crt.sh downloads certificates valid on the run date, newest first, cap 50; cache keeps only the SHA-256.
- Censys dropped (legacy API retired Sept 2026, new PAT auth not in Settings). DKIM dropped: discovering keys needs guessed selectors = bruteforce.
- RDAP/WHOIS emit NS relations only (no registrar/expiry model). Shodan emits country/ASN/tech only (ports need a model change). GeoIP = iptoasn TSV (stdlib), user-supplied file. Dorks = plain function, not a registered plugin, only dorkint `site` templates (MIT attribution).
- Follow-ups (out of zone): `ArchivedURL._path` validator should reject `;`/`%3F`/`%23`; report must attribute Shodan data; README "data sources & usage policies" table.

Rules: Conventional Commits, one atomic commit per action below, TDD (test first), passive only, scope first, tests fully mocked (respx), coverage >= 80 %.

## Actions

- [x] feat(plugins): crtsh
- [x] feat(plugins): dns records (A/AAAA/CNAME/MX/TXT/NS); `_dmarc` built only here from a validated domain (`_domainkey` dropped, see decisions)
- [x] feat(plugins): spf/dmarc parsing
- [x] feat(plugins): rdap (contacts dropped via privacy filters)
- [x] feat(plugins): whois fallback
- [x] feat(plugins): asn via Team Cymru DNS
- [x] feat(plugins): geoip (offline dataset, iptoasn/GeoLite2 - note licence)
- [x] feat(plugins): wayback CDX (no query strings kept)
- [ ] feat(plugins): shodan (read-only, API key optional)
- ~~feat(plugins): censys (read-only, API key optional)~~ dropped by the user 2026-11-21
- [ ] feat(plugins): dorks generator (reuse/optional dependency on sibling project dorkint; never executes searches)
- [ ] docs(plugins): verify each module docstring states the traffic it emits
- [ ] Review + merge branch into main
