# AGENTS.md — SurfaceMap

Invariants guide + repo map for any agent (Claude Code or other) working on
this project.

## Stack

Python 3.11+ (local: 3.11.9), `src/` layout, packaged with `pyproject.toml`.
Planned dependencies (to be confirmed against `pyproject.toml` once it exists):
Typer (CLI), httpx + asyncio (collection), pydantic / pydantic-settings
(model + config), dnspython, SQLite (stdlib, cache), NetworkX, Neo4j driver
(optional), Jinja2 + Cytoscape.js (report), pytest + respx + pytest-cov, ruff.

## Repository map

```text
src/surfacemap/
  cli.py, config.py     Typer CLI, settings loaded from .env
  scope.py              scope.yaml guard: refuses any out-of-scope domain
  privacy.py            personal-data filters (whois contacts, emails, query strings)
  models/               pydantic entities, relations, observations, findings
  collect/              async engine, httpx client, rate limiter, SQLite cache
  plugins/              one passive source per module (crtsh, dns, rdap_whois, asn_geo, wayback, shodan, censys, dorks)
  graph/                observation merge, NetworkX / Neo4j export, centrality metrics
  risk/                 rule engine, one explainable rule per file in rules/
  report/               self-contained HTML report (Jinja2 + inlined Cytoscape.js)
tests/                  pytest, network fully mocked (respx), fixtures/ = recorded API responses
evaluation/             per-source Venn, Amass/Subfinder passive benchmark, results/
docs/                   architecture (Mermaid), sources & limits, methodology
crew/                   task lifecycle (single source of truth for work tracking)
```

## Verified commands

Run from the repo root (Windows: `.venv/Scripts/`, Linux/macOS: `.venv/bin/`).

```bash
py -3.11 -m venv .venv                      # Linux/macOS: python3.11 -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m pytest              # tests + coverage gate (80 %)
.venv/Scripts/ruff check . && .venv/Scripts/ruff format --check .
.venv/Scripts/surfacemap scope check www.logan-villard.fr   # needs ./scope.yaml (gitignored)
```

Do not pipe rich/typer output into `head` on Windows: the closed pipe raises a
spurious `OSError: [Errno 22]` traceback.

## Code rules

- **Passive only**: no port scan, no bruteforce, no HTTP request to the target
  or its subdomains. Allowed traffic: third-party public sources (crt.sh, RDAP,
  Wayback CDX, Team Cymru, Shodan/Censys read-only) and DNS resolution through a
  resolver. Any new plugin must state its traffic in its module docstring.
- **Scope first**: every entry point goes through `scope.py`. Out-of-scope nodes
  (e.g. a CNAME target on a CDN) are recorded and DNS-resolved, never enriched further.
- **No personal data**: everything a plugin emits passes through `privacy.py`
  before entering the graph. No individual names or emails, ever.
- Plugins never mutate the graph: they return `Observation` objects; `graph/builder.py` merges.
- One risk rule = one file, with `rationale`, `evidence` and `remediation`.
- Tests never hit the network (respx mocks; CI must pass offline). Coverage ≥ 80 %.
- Respect each API's terms and rate limits via `collect/ratelimit.py`; no limit bypass.
- Full typing, ruff clean, no `print` for logging (use `logging`).

## Secrets and boundaries

API keys (Shodan, Censys, …) live only in `.env` (gitignored), loaded by
`config.py`; `.env.example` lists the variables with empty values. Keys are
never logged, never written to the cache, never included in the HTML report.
`scope.yaml` is gitignored (`scope.example.yaml` is committed). See `SECURITY.md`.

## Documentation routing

- Product vision / scope: `PRODUCT.md`.
- Contribution conventions: `CONTRIBUTING.md`.
- Security limits: `SECURITY.md`.
- Global context guide: `crew/CLAUDE_CONTEXT/AGENTS.md`.
