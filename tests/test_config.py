from pathlib import Path

import pytest

from domain_mapper.config import Settings


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "DOMAIN_MAPPER_SHODAN_API_KEY",
        "DOMAIN_MAPPER_CENSYS_API_ID",
        "DOMAIN_MAPPER_CENSYS_API_SECRET",
        "DOMAIN_MAPPER_CACHE_DIR",
    ):
        monkeypatch.delenv(var, raising=False)


def test_api_keys_are_optional() -> None:
    settings = Settings(_env_file=None)
    assert settings.shodan_api_key is None
    assert not settings.shodan_enabled
    assert not settings.censys_enabled


def test_reads_keys_from_env_file(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("DOMAIN_MAPPER_SHODAN_API_KEY=abc123\n", encoding="utf-8")
    settings = Settings(_env_file=env)
    assert settings.shodan_enabled
    assert settings.shodan_api_key is not None
    assert settings.shodan_api_key.get_secret_value() == "abc123"


def test_environment_overrides_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = tmp_path / ".env"
    env.write_text("DOMAIN_MAPPER_SHODAN_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setenv("DOMAIN_MAPPER_SHODAN_API_KEY", "from-env")
    settings = Settings(_env_file=env)
    assert settings.shodan_api_key is not None
    assert settings.shodan_api_key.get_secret_value() == "from-env"


def test_censys_needs_both_id_and_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOMAIN_MAPPER_CENSYS_API_ID", "id-only")
    assert not Settings(_env_file=None).censys_enabled
    monkeypatch.setenv("DOMAIN_MAPPER_CENSYS_API_SECRET", "s3cret")
    assert Settings(_env_file=None).censys_enabled


def test_secrets_never_appear_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOMAIN_MAPPER_SHODAN_API_KEY", "super-secret-key")
    settings = Settings(_env_file=None)
    assert "super-secret-key" not in repr(settings)
    assert "super-secret-key" not in str(settings.model_dump())


def test_empty_value_in_env_file_means_disabled(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("DOMAIN_MAPPER_SHODAN_API_KEY=\n", encoding="utf-8")
    assert not Settings(_env_file=env).shodan_enabled


def test_cache_dir_default_and_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert Settings(_env_file=None).cache_dir == Path(".cache")
    monkeypatch.setenv("DOMAIN_MAPPER_CACHE_DIR", str(tmp_path))
    assert Settings(_env_file=None).cache_dir == tmp_path


def test_shipped_env_example_disables_all_sources() -> None:
    example = Path(__file__).resolve().parents[1] / ".env.example"
    settings = Settings(_env_file=example)
    assert not settings.shodan_enabled
    assert not settings.censys_enabled
