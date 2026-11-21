from importlib.metadata import version

import domain_mapper


def test_version_matches_installed_metadata() -> None:
    assert domain_mapper.__version__ == version("domain-mapper")
