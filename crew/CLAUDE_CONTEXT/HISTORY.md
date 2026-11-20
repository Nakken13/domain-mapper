# History of completed tasks

One entry per finished task (code complete): what, when, key files/commits.
Project context memory — do not summarize, keep the details that would help a
future session understand why a decision was made.

<!-- Example:
## <task slug> — YYYY-MM-DD
What: ...
Key files/commits: ...
-->

## phase-0-foundations — 2026-11-20
What: packaging + CI + config (pydantic SecretStr for API keys) + scope guard (domain normalization, exact-label suffix match, "most specific entry decides" fail-closed fix in 42e976e) + Typer CLI `scope check`. 64 tests, 100 % coverage.
Key files/commits: ba88ab1..2e2ed0a on main (`src/surfacemap/scope.py`, `config.py`, `cli.py`).
Note: phase 0 skipped crew tracking and review and went straight to main.
Tests: none — covered by tests/test_scope.py, tests/test_cli.py, tests/test_config.py

## data-model — 2026-11-20
What: phase 1 data model. Frozen pydantic entities (Domain, IPAddress, ASN, Certificate, Technology, ArchivedURL) with canonical `type:value` ids (IDNA fqdn via scope.normalize_domain, compressed IP, bare ASN, lowercase sha256; cert SANs in the same IDNA form, wildcards kept). Typed Relation (endpoint kinds checked from id prefix, `Relation.between` preferred) + Provenance (query refused if it carries a credential). Observation (only plugin output) + Finding + ordered Severity (comparison with plain str raises). privacy.py: `redact_registration` is an ALLOW-list of technical RDAP/WHOIS fields (a deny-list missed python-whois org/state/zipcode/phone/raw text), `redact_observation` scrubs emails from every string field + relation endpoints and re-validates. graph/builder.py: SurfaceGraph merges redacted observations, per-node/edge source sets (Venn input), order-independent conflict rules (sorted tuple union, None filled, last_seen max, else min so in_scope False wins).
Key files/commits: c089a9b..8618e6c on crew/batch-a (`src/surfacemap/models/`, `privacy.py`, `graph/builder.py`, `graph/__init__.py` package file). Deep review: hide_input_in_errors (secrets were echoed in ValidationError text), generic scrub (issuer/path emails leaked), Unicode/%40 emails. Security pass: email regex was quadratic (103 s on a 60 kB string) -> RFC length caps (0.26 s).
Follow-ups: (1) once config.py exposes keys, reject any Provenance.query containing a configured secret value (exact match) instead of relying only on name regex; (2) scope.normalize_domain echoes the raw input in its error text, so an email given as a domain lands in error messages; (3) declare merge policy per field (Annotated metadata) when a second "latest wins" field appears; (4) node/edge iteration order follows arrival, so exports must sort.
Tests: none — risky zone (privacy) but fully covered by tests/test_privacy.py, tests/test_models_*.py, tests/test_graph_builder.py (171 tests, 100 % coverage)
