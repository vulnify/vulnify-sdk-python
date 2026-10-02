"""OpenAI Agents + Vulnify: a FunctionTool runs only when Vulnify allows it.

pip install 'vulnify[openai-agents]'
"""

import os

from agents import Agent, Runner, function_tool

from vulnify import Vulnify
from vulnify.adapters import guard_openai_agents_tool

# Production API by default. Local: VULNIFY_BASE_URL=http://localhost:3000
vulnify = Vulnify(api_key=os.environ["VULNIFY_API_KEY"])


@function_tool
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


# BLOCK returns the reason to the model. REVIEW waits when wait= is set.
export_customers = guard_openai_agents_tool(vulnify, export_customers, describe_export, wait={"timeout": 120})

sales = Agent(name="Sales assistant", instructions="Be careful with customer data.", tools=[export_customers])

if __name__ == "__main__":
    print(Runner.run_sync(sales, "Export 12 customers"))
