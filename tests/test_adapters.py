import asyncio
import inspect
import unittest
from types import SimpleNamespace

from vulnify import Decision, Vulnify, VulnifyBlockedError
from vulnify.adapters import (
    alanggraph_tool_guard,
    crewai_before_tool_call,
    guard_crewai_tool,
    guard_langchain_tool,
    guard_mcp_client,
    guard_mcp_handler,
    guard_openai_agents_tool,
    langgraph_tool_guard,
)


class FakeVulnify(Vulnify):
    """Answers a fixed decision and records every check (no HTTP)."""

    def __init__(self, decision, final_decision=None):
        super().__init__(api_key="k")
        self.decision = decision
        self.final_decision = final_decision
        self.checks = []

    def check(self, **action):
        self.checks.append(action)
        return Decision(
            id="evt-1",
            decision=self.decision,
            final_decision=self.final_decision,
            reasons=["too many records"],
        )


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


def _mcp_error_text(result):
    if isinstance(result, dict):
        assert result["isError"] is True
        return result["content"][0]["text"]
    assert result.is_error is True
    return result.content[0].text


class LangChainTool:
    def __init__(self):
        self.calls = []

    def _run(self, rows):
        self.calls.append(rows)
        return f"exported {rows}"

    async def _arun(self, rows):
        return self._run(rows)

    def invoke(self, tool_input, config=None):
        return self._run(**tool_input)


class InvokeOnlyTool:
    def __init__(self):
        self.calls = []

    def invoke(self, tool_input, config=None):
        self.calls.append(tool_input)
        return "done"

    def call(self, tool_input):
        self.calls.append(("call", tool_input))
        return "called"


class FunctionTool:
    def __init__(self):
        self.calls = []

    async def on_invoke_tool(self, ctx, tool_input):
        self.calls.append(tool_input)
        return "exported"


class LangChainTests(unittest.TestCase):
    def test_import_does_not_pull_in_langchain(self):
        import sys

        self.assertNotIn("langchain_core", sys.modules)

    def test_base_tool_checks_once_and_answers_the_reason(self):
        v = FakeVulnify("ALLOW")
        tool = guard_langchain_tool(v, LangChainTool(), describe_export)
        self.assertEqual(tool.invoke({"rows": 3}), "exported 3")
        self.assertEqual(v.checks[0]["records_affected"], 3)
        self.assertEqual(asyncio.run(tool._arun(rows=4)), "exported 4")
        self.assertEqual(len(v.checks), 2)

        blocked = guard_langchain_tool(FakeVulnify("BLOCK"), LangChainTool(), describe_export)
        self.assertEqual(blocked.invoke({"rows": 3}), "Vulnify BLOCK: too many records")
        self.assertEqual(blocked.calls, [])
        raising = guard_langchain_tool(FakeVulnify("BLOCK"), LangChainTool(), describe_export, on_blocked="raise")
        with self.assertRaises(VulnifyBlockedError):
            raising.invoke({"rows": 3})

    def test_invoke_only_tool_guards_invoke_and_call(self):
        tool = guard_langchain_tool(FakeVulnify("BLOCK"), InvokeOnlyTool(), describe_export)
        self.assertEqual(tool.invoke({"rows": 1}), "Vulnify BLOCK: too many records")
        self.assertEqual(tool.call({"rows": 1}), "Vulnify BLOCK: too many records")
        self.assertEqual(tool.calls, [])
        with self.assertRaises(ValueError):
            guard_langchain_tool(FakeVulnify("ALLOW"), object(), describe_export)

    def test_review_follows_final_decision(self):
        allowed = guard_langchain_tool(FakeVulnify("REVIEW", final_decision="ALLOW"), LangChainTool(), describe_export)
        self.assertEqual(allowed.invoke({"rows": 2}), "exported 2")
        blocked = guard_langchain_tool(FakeVulnify("REVIEW", final_decision="BLOCK"), LangChainTool(), describe_export)
        self.assertIn("too many records", blocked.invoke({"rows": 2}))
        self.assertEqual(blocked.calls, [])


class OpenAIAgentsTests(unittest.TestCase):
    def test_import_does_not_pull_in_the_agents_package(self):
        import sys

        self.assertNotIn("agents", sys.modules)

    def test_function_tool_parses_json_and_returns_the_block_message(self):
        v = FakeVulnify("ALLOW")
        tool = guard_openai_agents_tool(v, FunctionTool(), describe_export)
        self.assertEqual(asyncio.run(tool.on_invoke_tool({}, '{"rows": 3}')), "exported")
        self.assertEqual(tool.calls, ['{"rows": 3}'])
        self.assertEqual(v.checks[0]["records_affected"], 3)

        blocked = guard_openai_agents_tool(FakeVulnify("BLOCK"), FunctionTool(), describe_export)
        self.assertEqual(asyncio.run(blocked.on_invoke_tool({}, '{"rows": 42}')), "Vulnify BLOCK: too many records")
        self.assertEqual(blocked.calls, [])
        raising = guard_openai_agents_tool(FakeVulnify("BLOCK"), FunctionTool(), describe_export, on_blocked="raise")
        with self.assertRaises(VulnifyBlockedError):
            asyncio.run(raising.on_invoke_tool({}, '{"rows": 1}'))

    def test_execute_config_is_copied_and_invoke_shaped_tools_are_accepted(self):
        calls = []

        def execute(tool_input, context=None):
            calls.append((tool_input, context))
            return "exported"

        config = {"name": "export_customers", "description": "d", "execute": execute}
        guarded = guard_openai_agents_tool(FakeVulnify("ALLOW"), config, describe_export)
        self.assertEqual(guarded["name"], "export_customers")
        self.assertIs(config["execute"], execute)
        self.assertEqual(asyncio.run(guarded["execute"]({"rows": 3}, {"context": {}})), "exported")
        self.assertEqual(calls, [({"rows": 3}, {"context": {}})])

        calls.clear()
        blocked = guard_openai_agents_tool(FakeVulnify("BLOCK"), config, describe_export)
        self.assertEqual(asyncio.run(blocked["execute"]({"rows": 3})), "Vulnify BLOCK: too many records")
        self.assertEqual(calls, [])

        invoke_calls = []
        fn_tool = SimpleNamespace(type="function", name="export_customers", invoke=lambda ctx, raw: invoke_calls.append(raw) or "exported")
        guarded_fn = guard_openai_agents_tool(FakeVulnify("BLOCK"), fn_tool, describe_export)
        self.assertEqual(asyncio.run(guarded_fn.invoke({}, '{"rows": 9}')), "Vulnify BLOCK: too many records")
        self.assertEqual(invoke_calls, [])
        self.assertIsNot(guarded_fn.invoke, fn_tool.invoke)
        with self.assertRaises(ValueError):
            guard_openai_agents_tool(FakeVulnify("ALLOW"), {"name": "x"}, describe_export)

    def test_review_follows_final_decision_and_raw_strings_reach_describe(self):
        tool = guard_openai_agents_tool(FakeVulnify("REVIEW", final_decision="ALLOW"), FunctionTool(), describe_export)
        self.assertEqual(asyncio.run(tool.on_invoke_tool({}, '{"rows": 2}')), "exported")
        blocked = guard_openai_agents_tool(FakeVulnify("REVIEW", final_decision="BLOCK"), FunctionTool(), describe_export)
        self.assertIn("too many records", asyncio.run(blocked.on_invoke_tool({}, '{"rows": 2}')))
        self.assertEqual(blocked.calls, [])

        seen = []

        def describe(args):
            seen.append(args)
            return {"agent": "SalesBot", "action": "EXPORT_DATA", "resource": "Customer Database"}

        asyncio.run(guard_openai_agents_tool(FakeVulnify("BLOCK"), FunctionTool(), describe).on_invoke_tool({}, "not-json"))
        self.assertEqual(seen, [{"input": "not-json"}])


class McpSession:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments=None, **kwargs):
        self.calls.append((name, arguments, kwargs))
        return {"content": [{"type": "text", "text": "ok"}]}


class McpTests(unittest.TestCase):
    def test_import_does_not_pull_in_mcp(self):
        import sys

        self.assertNotIn("mcp", sys.modules)

    def test_handler_returns_an_error_result_and_keeps_the_signature(self):
        def export_customers(rows: int) -> str:
            """Export rows."""
            return f"exported {rows}"

        v = FakeVulnify("ALLOW")
        guarded = guard_mcp_handler(v, describe_export, export_customers)
        self.assertEqual(asyncio.run(guarded(rows=5)), "exported 5")
        self.assertEqual(v.checks[0]["records_affected"], 5)
        self.assertIn("rows", inspect.signature(guarded).parameters)
        self.assertEqual(guarded.__name__, "export_customers")

        calls = []

        def handler(args, extra=None):
            calls.append((args, extra))
            return "ran"

        blocked = guard_mcp_handler(FakeVulnify("BLOCK"), describe_export, handler)
        result = asyncio.run(blocked({"rows": 1}, {"request_id": "r"}))
        self.assertEqual(_mcp_error_text(result), "Vulnify BLOCK: too many records")
        self.assertEqual(calls, [])

        def boom(rows: int) -> str:
            raise RuntimeError("nope")

        with self.assertRaises(RuntimeError):
            asyncio.run(guard_mcp_handler(FakeVulnify("ALLOW"), describe_export, boom)(rows=1))

    def test_client_blocks_listed_tools_and_forwards_the_rest(self):
        session = guard_mcp_client(FakeVulnify("BLOCK"), McpSession(), {"export_customers": describe_export})
        result = asyncio.run(session.call_tool("export_customers", {"rows": 8}, read_timeout_seconds=1))
        self.assertEqual(_mcp_error_text(result), "Vulnify BLOCK: too many records")
        self.assertEqual(session.calls, [])

        v = FakeVulnify("ALLOW")
        allowed = guard_mcp_client(v, McpSession(), {"export_customers": describe_export})
        self.assertEqual(
            asyncio.run(allowed.call_tool("export_customers", {"rows": 8}, read_timeout_seconds=1)),
            {"content": [{"type": "text", "text": "ok"}]},
        )
        self.assertEqual(allowed.calls, [("export_customers", {"rows": 8}, {"read_timeout_seconds": 1})])
        self.assertEqual(asyncio.run(allowed.call_tool("search_docs", {})), {"content": [{"type": "text", "text": "ok"}]})
        self.assertEqual(len(v.checks), 1)

    def test_review_follows_final_decision(self):
        def export_customers(rows: int) -> str:
            return f"exported {rows}"

        allowed = guard_mcp_handler(FakeVulnify("REVIEW", final_decision="ALLOW"), describe_export, export_customers)
        self.assertEqual(asyncio.run(allowed(rows=2)), "exported 2")
        blocked = guard_mcp_handler(FakeVulnify("REVIEW", final_decision="BLOCK"), describe_export, export_customers)
        self.assertIn("too many records", _mcp_error_text(asyncio.run(blocked(rows=2))))

        session = guard_mcp_client(
            FakeVulnify("REVIEW", final_decision="BLOCK"), McpSession(), {"export_customers": describe_export}
        )
        self.assertIn("too many records", _mcp_error_text(asyncio.run(session.call_tool("export_customers", {"rows": 1}))))
        self.assertEqual(session.calls, [])


if __name__ == "__main__":
    unittest.main()
