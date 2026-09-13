"""Drive the MCP surface with a real MCP client over Streamable HTTP.

Not a unit test: this is the interoperability check. It speaks the protocol through the SDK's own
client, over HTTP, against a running server — the only way to know the transport, the bearer-token
plumbing and the tool schemas actually work together rather than each working alone.

It found a real defect the first time it ran: the MCP app had been mounted under `/mcp`, which put
its own `/mcp` route at `/mcp/mcp` and answered 404 to every client.

    MCP_URL=https://host/mcp MCP_TOKEN=<bearer> uv run python scripts/mcp_smoke.py
"""

from __future__ import annotations

import asyncio
import os
import sys

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

URL = os.environ["MCP_URL"]
TOKEN = os.environ.get("MCP_TOKEN", "")
ACCOUNT = os.environ.get("MCP_ACCOUNT", "ACC-1041")
AMOUNT = int(os.environ.get("MCP_AMOUNT", "500"))


async def main() -> int:
    headers = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}
    async with (
        httpx.AsyncClient(headers=headers, timeout=60) as http,
        streamable_http_client(URL, http_client=http) as (read, write),
        ClientSession(read, write) as session,
    ):
        init = await session.initialize()
        print(f"server:   {init.server_info.name} {init.server_info.version}")
        print(f"protocol: {init.protocol_version}")

        tools = await session.list_tools()
        print(f"tools:    {sorted(t.name for t in tools.tools)}")

        ping = await session.call_tool("ping", {})
        print(f"ping:     is_error={ping.is_error}")

        credit = await session.call_tool("issue_credit", {"account": ACCOUNT, "amount": AMOUNT})
        body = credit.content[0].text if credit.content else ""
        print(f"credit:   is_error={credit.is_error} {' '.join(body.split())[:180]}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
