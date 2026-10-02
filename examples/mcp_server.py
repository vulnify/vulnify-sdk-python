"""MCP + Vulnify: server tools and client calls are checked before they run.

pip install 'vulnify[mcp]'

mcp 2 names the server class MCPServer. Older releases called it FastMCP.
"""

import os

from mcp.server import MCPServer

from vulnify import Vulnify
from vulnify.adapters import guard_mcp_client, guard_mcp_handler

# Production API by default. Local: VULNIFY_BASE_URL=http://localhost:3000
vulnify = Vulnify(api_key=os.environ["VULNIFY_API_KEY"])


def describe_export(args):
    return {
        "agent": "SalesBot",
        "action": "EXPORT_DATA",
        "resource": "Customer Database",
        "records_affected": args.get("rows"),
    }


async def export_customers(rows: int) -> str:
    """Export customer records."""
    return f"exported {rows}"


server = MCPServer("sales")
server.tool()(guard_mcp_handler(vulnify, describe_export, export_customers))


async def call_export(session):
    # Listed tools are checked. A block comes back as an MCP error result.
    guarded = guard_mcp_client(vulnify, session, {"export_customers": describe_export})
    return await guarded.call_tool("export_customers", {"rows": 10})


if __name__ == "__main__":
    server.run()
