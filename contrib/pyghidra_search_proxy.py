#!/usr/bin/env python3
"""Tool Search proxy for pyghidra-mcp.

pyghidra-mcp exposes ~18 tools. Some MCP clients send every tool definition to
the model on each request, which can add several thousand tokens of context
before you've asked anything. This wrapper runs pyghidra-mcp as a backend and
puts a FastMCP ``BM25SearchTransform`` in front of it, so clients see only a
small surface and discover the rest on demand:

    search_tools          - find tools by keyword (BM25 ranking)
    call_tool             - invoke any tool by name
    list_project_binaries - always-visible orientation tool
    import_binary         - always-visible orientation tool

All other tools remain fully callable via ``call_tool``. In practice this drops
the advertised tool definitions from ~5,800 tokens to a few hundred for clients
that load the full catalog eagerly (e.g. opencode). Clients that already
lazy-load tools (e.g. Claude Code) are unaffected.

Requirements:
    pip install 'pyghidra-mcp[search]'   # pulls in fastmcp

Usage:
    Point your MCP client at this script instead of pyghidra-mcp directly. Any
    arguments are forwarded to the backend pyghidra-mcp process unchanged, e.g.:

        python contrib/pyghidra_search_proxy.py --project-path /path/to/project

    The backend is launched via the installed ``pyghidra-mcp`` console script,
    so it inherits the current environment (GHIDRA_INSTALL_DIR, etc.).
"""

import json
import os
import sys
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy
from fastmcp.server.transforms.search import BM25SearchTransform
from fastmcp.tools import Tool


class CoercingBM25SearchTransform(BM25SearchTransform):
    """BM25 search transform whose ``call_tool`` also accepts ``arguments`` as a
    JSON string, not just an object.

    Some MCP clients/models (e.g. opencode + qwen3.7-plus) serialize the
    ``call_tool`` ``arguments`` value as a JSON string. FastMCP's stock
    ``call_tool`` types it as ``dict | None``, so a string fails pydantic
    validation with ``Input should be a valid dictionary``. This subclass
    ``json.loads`` a string argument before forwarding; dict/None are unchanged.
    """

    def _make_call_tool(self) -> Tool:
        transform = self

        async def call_tool(
            name: Annotated[str, "The name of the tool to call"],
            arguments: Annotated[
                dict[str, Any] | str | None,
                "Arguments to pass to the tool (object, or a JSON string)",
            ] = None,
            ctx: Context = None,  # type: ignore[assignment]
        ):
            """Call a tool by name with the given arguments.

            Use this to execute tools discovered via search_tools.
            """
            if isinstance(arguments, str):
                arguments = json.loads(arguments) if arguments.strip() else None
            if name in {transform._call_tool_name, transform._search_tool_name}:
                raise ValueError(
                    f"'{name}' is a synthetic search tool and cannot be called "
                    "via the call_tool proxy"
                )
            return await ctx.fastmcp.call_tool(name, arguments)

        return Tool.from_function(fn=call_tool, name=self._call_tool_name)


def main() -> None:
    # Forward all CLI args through to the backend pyghidra-mcp process and force
    # stdio (the transport this proxy speaks to its backend over).
    backend_args = sys.argv[1:]
    if "--transport" not in backend_args:
        backend_args += ["--transport", "stdio"]

    transport = StdioTransport(
        command="pyghidra-mcp",
        args=backend_args,
        env={**os.environ},
        keep_alive=True,
    )

    proxy = create_proxy(
        transport,
        name="pyghidra-search",
        transforms=[
            CoercingBM25SearchTransform(
                max_results=5,
                always_visible=["list_project_binaries", "import_binary"],
            )
        ],
    )

    print("Starting pyghidra-mcp Tool Search proxy...", file=sys.stderr)
    proxy.run()


if __name__ == "__main__":
    main()
