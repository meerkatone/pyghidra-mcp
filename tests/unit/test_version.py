import pytest
import tomli
from click.testing import CliRunner
from fastmcp import Client

from pyghidra_mcp import __version__
from pyghidra_mcp.server import main, mcp


def test_version_matches_pyproject():
    """Ensures that the version in pyproject.toml and __init__.py match."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)
    assert __version__ == pyproject["project"]["version"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_server_reports_package_version_to_mcp_clients(monkeypatch, mode):
    monkeypatch.setattr(mcp, "_pyghidra_context", object(), raising=False)
    async with Client(mcp, mode=mode) as client:
        assert client.server_info is not None
        assert client.server_info.version == __version__


def test_server_cli_reports_package_version():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
