# CONTRIBUTING.md — SurfaceMap

## Branches

`main` always green. Work branches: `feat/<slug>`, `fix/<slug>`, `docs/<slug>`.

## Commits

Conventional Commits (`feat(scope): ...`, `fix(dns): ...`, `test:`, `docs:`,
`ci:`, `chore:`). Small and atomic: one logical change per commit, each commit
leaves ruff + pytest green.

## Pull requests

CI (GitHub Actions: ruff + pytest with coverage ≥ 80 %) must pass before
merge. No real network call in tests.
