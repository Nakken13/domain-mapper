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
