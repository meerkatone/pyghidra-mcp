import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_stdio_client_initialization(server_params):
    """Test stdio client initialization."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            result = await session.initialize()

            # Check that we got a proper response
            assert result is not None
            # The low-level SDK client retains handshake-era negotiation.
            assert str(result.protocol_version) == "2025-11-25"


@pytest.mark.asyncio
async def test_stdio_client_list_tools(server_params):
    """Test listing available tools."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # List available tools
            tools = await session.list_tools()

            # Check that we got a response
            assert tools is not None
            assert {tool.name for tool in tools.tools} == {
                "list_project_binaries",
                "list_project_binary_metadata",
                "search_tools",
                "call_tool",
            }


@pytest.mark.asyncio
async def test_stdio_client_list_resources(server_params):
    """Test listing available resources."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # List available resources
            resources = await session.list_resources()

            # Check that we got a response
            assert resources is not None
