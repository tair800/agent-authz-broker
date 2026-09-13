"""Drive the deployed MCP surface with a real MCP client over Streamable HTTP.

Not a unit test: this is the interoperability check. It speaks the protocol through the SDK's own
client, over HTTP, against a running server -- which is the only way to know the transport, the
bearer-token plumbing and the tool schemas actually work together.

    MCP_URL=https://host/mcp/ MCP_TOKEN=<bearer> uv run python scripts/mcp_smoke.py
"""

import asyncio
import os
import sys

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

URL = os.environ["MCP_URL"]
TOKEN = os.environ.get("MCP_TOKEN", "")


async def main() -> int:
    headers = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}
    async with httpx.AsyncClient(headers=headers, timeout=60) as http:
        async with streamable_http_client(URL, http_client=http) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                print(f"server:   {init.server_info.name} {init.server_info.version}")
                print(f"protocol: {init.protocol_version}")

                tools = await session.list_tools()
                names = sorted(t.name for t in tools.tools)
                print(f"tools:    {names}")

                ping = await session.call_tool("ping", {})
                print(f"ping:     isError={ping.is_error}")

                credit = await session.call_tool(
                    "issue_credit", {"account": "ACC-1041", "amount": 500}
                )
                body = credit.content[0].text if credit.content else ""
                print(f"credit:   isError={credit.is_error} {body[:200]}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
