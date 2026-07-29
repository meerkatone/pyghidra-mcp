import json

import pytest
from fastmcp import Client, FastMCP

from pyghidra_mcp.server import CoercingBM25SearchTransform, mcp


@pytest.mark.asyncio
async def test_server_negotiates_current_protocol_and_exposes_search_surface():
    mcp._pyghidra_context = object()

    async with Client(mcp) as client:
        assert str(client.protocol_version) == "2026-07-28"
        tools = await client.list_tools()
        assert {tool.name for tool in tools} == {
            "list_project_binaries",
            "list_project_binary_metadata",
            "search_tools",
            "call_tool",
        }


@pytest.mark.asyncio
async def test_call_tool_accepts_json_string_arguments():
    server = FastMCP(
        "test",
        transforms=[CoercingBM25SearchTransform(always_visible=[])],
    )

    @server.tool
    def add(left: int, right: int) -> int:
        """Add two integers."""
        return left + right

    async with Client(server) as client:
        result = await client.call_tool(
            "call_tool",
            {"name": "add", "arguments": json.dumps({"left": 2, "right": 3})},
        )

    assert result.is_error is False
    assert result.data == 5
