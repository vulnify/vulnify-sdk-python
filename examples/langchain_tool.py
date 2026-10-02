"""LangChain + Vulnify: the export tool runs only when Vulnify allows it.

pip install 'vulnify[langchain]'
"""

import os

from langchain_core.tools import tool

from vulnify import Vulnify
from vulnify.adapters import guard_langchain_tool

# Production API by default. Local: VULNIFY_BASE_URL=http://localhost:3000
vulnify = Vulnify(api_key=os.environ["VULNIFY_API_KEY"])


@tool
def export_customers(rows: int) -> str:
    """Export customer records."""
    return f"exported {rows}"


def describe_export(args):
    return {
        "agent": "SalesBot",
        "action": "EXPORT_DATA",
        "resource": "Customer Database",
        "records_affected": args.get("rows"),
    }


export_customers = guard_langchain_tool(vulnify, export_customers, describe_export)

if __name__ == "__main__":
    print(export_customers.invoke({"rows": 3}))
