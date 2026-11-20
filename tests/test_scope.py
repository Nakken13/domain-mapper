from datetime import date
from pathlib import Path

import pytest

from surfacemap.scope import (
    InvalidDomainError,
    OutOfScopeError,
    Scope,
    ScopeFileError,
    normalize_domain,
)

TODAY = date(2026, 11, 20)


def write_scope(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(body, encoding="utf-8")
    return path


@pytest.fixture
def scope(tmp_path: Path) -> Scope:
    return Scope.load(
        write_scope(
            tmp_path,
            """
authorized:
  - domain: logan-villard.fr
    authorization: owner
    expires: 2027-06-30
  - domain: rootonly.example
    include_subdomains: false
    authorization: "written authorization ref. 2026-001"
  - domain: old.example
    authorization: "expired engagement"
    expires: 2026-01-31
  - domain: café.example
    authorization: owner
""",
        ),
    )


# --- normalization -----------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("logan-villard.fr", "logan-villard.fr"),
        ("  WWW.Logan-Villard.FR.  ", "www.logan-villard.fr"),
        ("café.example", "xn--caf-dma.example"),
        ("xn--caf-dma.example", "xn--caf-dma.example"),
    ],
)
def test_normalize_domain(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "https://logan-villard.fr",
        "logan-villard.fr/path",
        "user@logan-villard.fr",
        "logan villard.fr",
        "1.2.3.4",
        "::1",
        "-bad.example",
        "bad-.example",
        "a..example",
        "*.logan-villard.fr",
        "x" * 64 + ".example",
        ("a" * 60 + ".") * 5 + "example",
    ],
)
def test_normalize_domain_rejects_invalid(raw: str) -> None:
    with pytest.raises(InvalidDomainError):
        normalize_domain(raw)


# --- matching ----------------------------------------------------------------


def test_root_domain_is_allowed(scope: Scope) -> None:
    decision = scope.check("logan-villard.fr", today=TODAY)
    assert decision.allowed
    assert decision.entry is not None
    assert decision.entry.domain == "logan-villard.fr"


def test_subdomain_is_allowed_by_default(scope: Scope) -> None:
    assert scope.check("dev.api.logan-villard.fr", today=TODAY).allowed


def test_input_is_normalized_before_matching(scope: Scope) -> None:
    assert scope.check("WWW.Logan-Villard.FR.", today=TODAY).allowed


def test_idn_entry_matches_punycode_input(scope: Scope) -> None:
    assert scope.check("www.xn--caf-dma.example", today=TODAY).allowed


@pytest.mark.parametrize(
    "lookalike",
    [
        "evil-logan-villard.fr",
        "logan-villard.fr.evil.com",
        "logan-villard.com",
        "villard.fr",
        "fr",
    ],
)
def test_lookalike_domains_are_refused(scope: Scope, lookalike: str) -> None:
    decision = scope.check(lookalike, today=TODAY)
    assert not decision.allowed
    assert decision.entry is None


def test_subdomain_refused_when_include_subdomains_is_false(scope: Scope) -> None:
    assert scope.check("rootonly.example", today=TODAY).allowed
    decision = scope.check("www.rootonly.example", today=TODAY)
    assert not decision.allowed
    assert "subdomain" in decision.reason


def test_expired_authorization_is_refused(scope: Scope) -> None:
    decision = scope.check("old.example", today=TODAY)
    assert not decision.allowed
    assert "expired" in decision.reason


def test_authorization_valid_on_its_expiry_day(scope: Scope) -> None:
    assert scope.check("logan-villard.fr", today=date(2027, 6, 30)).allowed
    assert not scope.check("logan-villard.fr", today=date(2027, 7, 1)).allowed


def test_check_defaults_to_current_date(scope: Scope) -> None:
    assert not scope.check("old.example").allowed


def test_invalid_input_is_refused_not_crashing(scope: Scope) -> None:
    decision = scope.check("https://logan-villard.fr", today=TODAY)
    assert not decision.allowed
    assert "invalid" in decision.reason


def test_require_returns_normalized_domain(scope: Scope) -> None:
    assert scope.require("API.logan-villard.fr", today=TODAY) == "api.logan-villard.fr"


def test_require_raises_when_out_of_scope(scope: Scope) -> None:
    with pytest.raises(OutOfScopeError, match=r"evil-logan-villard\.fr"):
        scope.require("evil-logan-villard.fr", today=TODAY)


# --- file loading ------------------------------------------------------------


def test_missing_file_points_to_example(tmp_path: Path) -> None:
    with pytest.raises(ScopeFileError, match=r"scope\.example\.yaml"):
        Scope.load(tmp_path / "scope.yaml")


@pytest.mark.parametrize(
    "body",
    [
        "",
        "authorized: []",
        "authorized: not-a-list",
        "- just a list",
        "authorized:\n  - domain: logan-villard.fr\n",
        "authorized:\n  - domain: logan-villard.fr\n    authorization: '  '\n",
        "authorized:\n  - domain: fr\n    authorization: owner\n",
        "authorized:\n  - domain: 'https://x.fr'\n    authorization: owner\n",
        "authorized:\n  - domain: x.fr\n    authorization: owner\n    unknown_key: 1\n",
        "authorized: [unclosed",
    ],
)
def test_malformed_scope_file_is_rejected(tmp_path: Path, body: str) -> None:
    with pytest.raises(ScopeFileError):
        Scope.load(write_scope(tmp_path, body))


def test_shipped_example_is_valid() -> None:
    example = Path(__file__).resolve().parents[1] / "scope.example.yaml"
    loaded = Scope.load(example)
    assert loaded.entries


def test_specific_child_entry_wins_over_restrictive_parent(tmp_path: Path) -> None:
    loaded = Scope.load(
        write_scope(
            tmp_path,
            """
authorized:
  - domain: parent.example
    include_subdomains: false
    authorization: owner
  - domain: api.parent.example
    authorization: owner
""",
        ),
    )
    assert loaded.check("v2.api.parent.example", today=TODAY).allowed
    assert not loaded.check("www.parent.example", today=TODAY).allowed


def test_restrictive_child_entry_is_not_overridden_by_parent(tmp_path: Path) -> None:
    loaded = Scope.load(
        write_scope(
            tmp_path,
            """
authorized:
  - domain: parent.example
    authorization: owner
  - domain: api.parent.example
    include_subdomains: false
    authorization: owner
""",
        ),
    )
    assert loaded.check("api.parent.example", today=TODAY).allowed
    decision = loaded.check("v2.api.parent.example", today=TODAY)
    assert not decision.allowed
    assert "subdomains of api.parent.example" in decision.reason


def test_expired_child_entry_is_not_rescued_by_parent(tmp_path: Path) -> None:
    loaded = Scope.load(
        write_scope(
            tmp_path,
            """
authorized:
  - domain: parent.example
    authorization: owner
  - domain: client.parent.example
    authorization: "engagement ref. 42"
    expires: 2026-01-31
""",
        ),
    )
    decision = loaded.check("app.client.parent.example", today=TODAY)
    assert not decision.allowed
    assert "expired" in decision.reason
