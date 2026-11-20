from importlib.metadata import version

import surfacemap


def test_version_matches_installed_metadata() -> None:
    assert surfacemap.__version__ == version("surfacemap")
