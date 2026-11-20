# data-model

Phase 1: typed entities, relations, privacy redaction and deduplicated graph merge.

Branch: `feat/data-model`
Batch: A
Zone: `src/surfacemap/models/`, `src/surfacemap/privacy.py`, `src/surfacemap/graph/builder.py`, `tests/`
Depends on: none

Rules: Conventional Commits, one atomic commit per action below, TDD (test first), passive only, scope first, tests fully mocked (respx), coverage >= 80 %.

## Actions

- [x] feat(models): entity types with stable ids (`type:value`), frozen pydantic: Domain(fqdn,in_scope,records), IPAddress(address,country), ASN(number,holder,country), Certificate(sha256,issuer,not_before,not_after,sans), Technology(name,category,evidence), ArchivedURL(host,path,first_seen,last_seen, no query string)
- [x] feat(models): Relation (HAS_SUBDOMAIN, RESOLVES_TO, CNAME_TO, MX, NS, ANNOUNCED_BY, SECURED_BY, USES_TECH, ARCHIVED_AT) + Provenance(source, retrieved_at, query)
- [ ] feat(models): Observation and Finding (rule_id, Severity, title, rationale, evidence ids, remediation)
- [ ] feat(privacy): redaction filters (drop WHOIS/RDAP contacts, drop cert SANs containing '@', strip URL query strings)
- [ ] feat(graph): merge observations into a deduplicated graph, sources unioned per node (feeds the Venn diagram)
- [ ] Review + merge branch into main
