# evaluation

Phase 7: evaluation of sources and benchmark against Amass/Subfinder (passive mode). Target: logan-villard.fr (owned by the user, authorized).

Branch: `docs/evaluation`
Batch: G
Zone: `evaluation/`, `docs/`
Depends on: html-report.md (needs a working `scan`)

Rules: Conventional Commits, one atomic commit per action below, TDD (test first), passive only, scope first, tests fully mocked (respx), coverage >= 80 %.

## Actions

- [ ] feat(eval): per-source subdomain counts + Venn diagram
- [ ] feat(eval): Amass/Subfinder passive benchmark harness (coverage + run time) on logan-villard.fr
- [ ] docs(eval): results + interpretation of graph metrics
- [ ] Review + merge branch into main
