"""CrewAI + Vulnify: the export tool only runs when Vulnify allows it.

pip install crewai  (plus this package: pip install -e .)
"""

import os

from crewai import Agent, Crew, Task
from crewai.tools import BaseTool

from vulnify import Vulnify
from vulnify.adapters import guard_crewai_tool

# Production API by default. Local: VULNIFY_BASE_URL=http://localhost:3000
vulnify = Vulnify(api_key=os.environ["VULNIFY_API_KEY"])


class ExportCustomers(BaseTool):
    name: str = "export_customers"
    description: str = "Export customer records and email them to an address."

    def _run(self, rows: int, email: str) -> str:
        return f"Exported {rows} customers to {email}"


def describe_export(args):
    return {
        "agent": "SalesBot",
        "action": "EXPORT_DATA",
        "resource": "Customer Database",
        "destination": "INTERNAL" if str(args.get("email", "")).endswith("@yourcompany.com") else "EXTERNAL_EMAIL",
        "records_affected": args.get("rows"),
    }


# BLOCK: the tool answers Vulnify's reasons to the agent. REVIEW waits up to 2 minutes for a human.
export_tool = guard_crewai_tool(vulnify, ExportCustomers(), describe_export, wait={"timeout": 120})

# Alternative for every crew at once (the agent only sees "blocked by hook"):
#   from crewai.hooks import register_before_tool_call_hook
#   from vulnify.adapters import crewai_before_tool_call
#   register_before_tool_call_hook(crewai_before_tool_call(vulnify, {"export_customers": describe_export}))

sales = Agent(role="Sales assistant", goal="Help the sales team", backstory="Careful with customer data.", tools=[export_tool])
task = Task(description="Send all 12000 customers to partner@example.org", expected_output="What happened", agent=sales)

if __name__ == "__main__":
    print(Crew(agents=[sales], tasks=[task]).kickoff())
