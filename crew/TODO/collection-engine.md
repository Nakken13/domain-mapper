# collection-engine

Phase 2: caching, rate limiting, HTTP client, plugin contract and iterative asyncio engine.

Branch: `feat/collection-engine`
Batch: B
Zone: `src/surfacemap/collect/`, `src/surfacemap/plugins/base.py`, `tests/`
Depends on: data-model.md

Rules: Conventional Commits, one atomic commit per action below, TDD (test first), passive only, scope first, tests fully mocked (respx), coverage >= 80 %.

## Actions

- [ ] feat(collect): SQLite response cache with TTL (key = source + query)
- [ ] feat(collect): per-source token-bucket rate limiter
- [ ] feat(collect): httpx async client with retries and honest User-Agent
- [ ] feat(plugins): Plugin Protocol + registry (`plugins/base.py`)
- [ ] feat(collect): iterative asyncio engine: newly found subdomains re-fed to DNS; out-of-scope nodes recorded + DNS-resolved only, never enriched further (scope.require first)
- [ ] Review + merge branch into main
