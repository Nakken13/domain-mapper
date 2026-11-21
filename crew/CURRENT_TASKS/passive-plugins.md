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
- [x] feat(plugins): shodan (read-only, API key optional)
- ~~feat(plugins): censys (read-only, API key optional)~~ dropped by the user 2026-11-21
- [x] feat(plugins): dorks generator (reuse/optional dependency on sibling project dorkint; never executes searches)
- [x] docs(plugins): verify each module docstring states the traffic it emits
- [ ] Review fixes (deep review 2026-11-21, verdict "with fixes"; item 1 done in the wayback email commit):
  - [x] crtsh `_minimize`: keep only identity lines that normalize as hostnames (S/MIME CN = person name reaches cache); `scrub_emails` on `issuer_name`
  - [ ] crtsh: download deadline from call start (`asyncio.timeout_at(start + DOWNLOAD_BUDGET)`), a slow search must not lose subdomains
  - [ ] dns/mailauth: DMARC empty "absent" only on scope roots (RFC 7489 § 6.6.3 fallback to org domain); multiple `v=DMARC1` → `dmarc_of` returns "invalid"
  - [x] wayback: emails encoded in a path (e.g. `%6A%61ne%40…`, fullwidth `＠`) dodge `scrub_emails`: NFKC + repeated `unquote` before scrubbing, or fail closed (cut the path at any remaining `%`) (background security review)
  - [x] crtsh: SECURED_BY edges only for in-scope hosts (same policy as wayback)
  - [ ] `_resolver.DnspythonResolver`: build the dnspython resolver lazily (no OS config read at registry creation)
  - [ ] geoip: `await asyncio.to_thread(_load, path)`; whois: `await writer.wait_closed()`; wayback: log when rows == CDX_LIMIT
  - [ ] `simplify` pass (deep size): shared root-only applies_to, `_is_ip_literal` reuse from collect/http.py, one JSON-or-FetchError helper, `try_normalize`, shared NS observation (rdap/whois), `_COUNTRY`/`is_global` dupes, provenance helper
  - Declined: Shodan hostnames as RESOLVES_TO (edge sources already distinguish Shodan); Shodan 404 noise (needs FetchError status in collect/http.py → follow-up)
- [ ] Review + merge branch into main (main has uncommitted crew/ index edits from the hook: ask the user before committing/stashing them)
