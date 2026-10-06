import asyncio
import json
import socket
import subprocess
import time

import aiohttp
import pytest
from fastmcp import Client
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import DecompiledFunction


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def streamable_project_args(tmp_path_factory):
    project_path = tmp_path_factory.mktemp("streamable-project")
    return ["--project-path", str(project_path), "--project-name", "streamable_client_project"]


@pytest.fixture(scope="module")
def streamable_base_url():
    return f"http://127.0.0.1:{_find_free_port()}"


@pytest.fixture(scope="module")
def streamable_server(test_binary, ghidra_env, streamable_project_args, streamable_base_url):
    """Fixture to start the pyghidra-mcp server in a separate process."""
    port = int(streamable_base_url.rsplit(":", 1)[1])
    proc = subprocess.Popen(
        [
            "python",
            "-m",
            "pyghidra_mcp",
            *streamable_project_args,
            "--wait-for-analysis",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            test_binary,
        ],
        env=ghidra_env,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    async def wait_for_server(timeout=240):
        async with aiohttp.ClientSession() as session:
            for _ in range(timeout):
                try:
                    async with session.get(f"{streamable_base_url}/mcp") as response:
                        if response.status in {400, 406}:
                            return
                except aiohttp.ClientConnectorError:
                    pass
                await asyncio.sleep(1)
            raise RuntimeError("Server did not start in time")

    try:
        asyncio.run(wait_for_server())
    except Exception:
        proc.terminate()
        proc.wait()
        raise

    time.sleep(2)

    yield test_binary, streamable_base_url
    proc.terminate()
    proc.wait()


@pytest.mark.asyncio
async def test_streamable_client_smoke(streamable_server, main_func_name):
    streamable_binary, streamable_base_url = streamable_server
    async with streamable_http_client(f"{streamable_base_url}/mcp") as (
        read_stream,
        write_stream,
    ):
        async with ClientSession(read_stream, write_stream) as session:
            # Initializing session...
            initialized = await session.initialize()
            assert str(initialized.protocol_version) == "2025-11-25"
            # Session initialized

            binary_name = PyGhidraContext._gen_unique_bin_name(streamable_binary)

            # Decompile a function
            name = main_func_name
            results = await session.call_tool(
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": name},
            )
            # We have results!
            assert results is not None
            content = json.loads(results.content[0].text)
            assert isinstance(content, list)
            assert len(content) == 1
            assert len(content[0].keys()) == len(DecompiledFunction.model_fields.keys())
            assert f"{name}(" in content[0]["code"]
            print(json.dumps(content, indent=2))


@pytest.mark.asyncio
async def test_modern_client_discovers_and_calls_decompiler(streamable_server, main_func_name):
    streamable_binary, streamable_base_url = streamable_server
    binary_name = PyGhidraContext._gen_unique_bin_name(streamable_binary)

    async with Client(f"{streamable_base_url}/mcp") as client:
        assert str(client.protocol_version) == "2026-07-28"
        tools = await client.list_tools()
        assert {tool.name for tool in tools} == {
            "list_project_binaries",
            "list_project_binary_metadata",
            "search_tools",
            "call_tool",
        }

        search = await client.call_tool("search_tools", {"query": "decompile function"})
        assert search.is_error is False
        assert any(
            isinstance(item, TextContent) and "decompile_function" in item.text
            for item in search.content
        )

        result = await client.call_tool(
            "call_tool",
            {
                "name": "decompile_function",
                "arguments": json.dumps(
                    {"binary_name": binary_name, "name_or_address": main_func_name}
                ),
            },
        )
        assert result.is_error is False
        assert isinstance(result.content[0], TextContent)
        content = json.loads(result.content[0].text)
        assert f"{main_func_name}(" in content[0]["code"]
