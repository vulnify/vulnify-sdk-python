import asyncio
import unittest
from types import SimpleNamespace

from vulnify import Decision, Vulnify, VulnifyBlockedError
from vulnify.adapters import alanggraph_tool_guard, crewai_before_tool_call, guard_crewai_tool, langgraph_tool_guard


class FakeVulnify(Vulnify):
    """Answers a fixed decision and records every check (no HTTP)."""

    def __init__(self, decision):
        super().__init__(api_key="k")
        self.decision = decision
        self.checks = []

    def check(self, **action):
        self.checks.append(action)
        return Decision(id="evt-1", decision=self.decision, reasons=["too many records"])


def describe_export(args):
    return {"agent": "SalesBot", "action": "EXPORT_DATA", "resource": "Customer Database", "records_affected": args.get("rows")}


class ExportTool:
    name = "export_customers"

    def __init__(self):
        self.calls = []

    def _run(self, rows):
        self.calls.append(rows)
        return f"exported {rows}"


class CrewAITests(unittest.TestCase):
    def test_before_hook_blocks_listed_tools_only(self):
        v = FakeVulnify("BLOCK")
        hook = crewai_before_tool_call(v, {"export_customers": describe_export})
        self.assertIs(hook(SimpleNamespace(tool_name="export_customers", tool_input={"rows": 500})), False)
        self.assertEqual(v.checks[0]["records_affected"], 500)
        self.assertIsNone(hook(SimpleNamespace(tool_name="search_docs", tool_input={})))
        self.assertEqual(len(v.checks), 1)
        self.assertIsNone(crewai_before_tool_call(FakeVulnify("ALLOW"), {"export_customers": describe_export})(
            SimpleNamespace(tool_name="export_customers", tool_input={"rows": 1})))

    def test_guarded_tool_runs_on_allow_and_answers_the_reason_on_block(self):
        tool = guard_crewai_tool(FakeVulnify("ALLOW"), ExportTool(), describe_export)
        self.assertEqual(tool._run(rows=3), "exported 3")
        blocked = guard_crewai_tool(FakeVulnify("BLOCK"), ExportTool(), describe_export)
        self.assertEqual(blocked._run(rows=3), "Vulnify BLOCK: too many records")
        self.assertEqual(blocked.calls, [])
        raising = guard_crewai_tool(FakeVulnify("BLOCK"), ExportTool(), describe_export, on_blocked="raise")
        with self.assertRaises(VulnifyBlockedError):
            raising._run(rows=3)


class LangGraphTests(unittest.TestCase):
    def request(self, name="export_customers", rows=7):
        return SimpleNamespace(tool_call={"name": name, "args": {"rows": rows}, "id": "call-1"})

    def test_wrap_tool_call_short_circuits_with_an_error_tool_message(self):
        executed = []
        wrap = langgraph_tool_guard(FakeVulnify("BLOCK"), {"export_customers": describe_export})
        msg = wrap(self.request(), lambda r: executed.append(r) or "ran")
        content = msg["content"] if isinstance(msg, dict) else msg.content
        self.assertEqual(content, "Vulnify BLOCK: too many records")
        self.assertEqual(executed, [])
        self.assertEqual(wrap(self.request(name="search_docs"), lambda r: "ran"), "ran")

    def test_wrap_tool_call_executes_when_allowed_and_async_variant(self):
        v = FakeVulnify("ALLOW")
        self.assertEqual(langgraph_tool_guard(v, {"export_customers": describe_export})(self.request(), lambda r: "ran"), "ran")
        self.assertEqual(v.checks[0]["records_affected"], 7)

        async def execute(request):
            return "ran async"

        awrap = alanggraph_tool_guard(FakeVulnify("ALLOW"), {"export_customers": describe_export})
        self.assertEqual(asyncio.run(awrap(self.request(), execute)), "ran async")
        ablocked = alanggraph_tool_guard(FakeVulnify("BLOCK"), {"export_customers": describe_export})
        msg = asyncio.run(ablocked(self.request(), execute))
        self.assertEqual(msg["content"] if isinstance(msg, dict) else msg.content, "Vulnify BLOCK: too many records")


if __name__ == "__main__":
    unittest.main()
