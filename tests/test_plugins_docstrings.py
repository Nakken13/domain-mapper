"""AGENTS.md rule: every plugin module states, in its docstring, the traffic it emits."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import domain_mapper.plugins

PLUGIN_DIR = Path(domain_mapper.plugins.__file__).parent
MODULES = sorted(p for p in PLUGIN_DIR.glob("*.py") if p.stem not in {"__init__", "base"})


def test_there_are_plugin_modules() -> None:
    assert len(MODULES) >= 10


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.stem)
def test_module_docstring_states_its_traffic(path: Path) -> None:
    docstring = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8"))) or ""
    traffic = [line for line in docstring.splitlines() if line.startswith("Traffic:")]
    assert traffic, f"{path.name}: no 'Traffic:' line in the module docstring"
