import tomli

from pyghidra_mcp import __version__


def test_version_matches_pyproject():
    """Ensures that the version in pyproject.toml and __init__.py match."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)
    assert __version__ == pyproject["project"]["version"]


def test_fastmcp_dependency_uses_verified_v4_beta():
    """Keep the server and development environments on the verified FastMCP build."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)

    expected = "fastmcp==4.0.0b2"
    assert expected in pyproject["project"]["dependencies"]
    assert expected in pyproject["dependency-groups"]["dev"]
    assert expected in pyproject["project"]["optional-dependencies"]["search"]
    assert expected in pyproject["project"]["optional-dependencies"]["dev"]
