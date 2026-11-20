# graph-export

Phase 5: graph export and centrality metrics.

Branch: `feat/graph-export`
Batch: E
Zone: `src/surfacemap/graph/` (except `src/surfacemap/graph/builder.py`), `docker-compose.yml`, `tests/`
Depends on: data-model.md

Rules: Conventional Commits, one atomic commit per action below, TDD (test first), passive only, scope first, tests fully mocked (respx), coverage >= 80 %.

## Actions

- [ ] feat(graph): NetworkX JSON/GraphML export
- [ ] feat(graph): Neo4j export + `docker-compose.yml` (optional)
- [ ] feat(graph): centrality metrics (degree, betweenness, articulation points) to flag critical nodes
- [ ] Review + merge branch into main
