"""Framework adapters for CrewAI and LangGraph.

Duck-typed on purpose: this package does not import CrewAI, LangGraph or LangChain, so it works with whichever
version you use. Every adapter takes a ``describe`` callable that maps the tool's arguments to the keyword
arguments of :meth:`Vulnify.check` (agent, action, resource, destination, records_affected, content, ...).
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, Mapping, Optional

from .client import Vulnify, VulnifyBlockedError

Describe = Callable[[Dict[str, Any]], Dict[str, Any]]


def _blocked_message(err: VulnifyBlockedError) -> str:
    return str(err)


def _check_allowed(vulnify: Vulnify, action: Dict[str, Any], wait: Optional[dict]) -> Optional[VulnifyBlockedError]:
    """None when the action may run; the blocking error otherwise (REVIEW waits when `wait` is given)."""
    try:
        vulnify.guard(lambda: None, wait=wait, **action)
        return None
    except VulnifyBlockedError as err:
        return err


# ---------------------------------------------------------------------------------------------------- CrewAI


def crewai_before_tool_call(vulnify: Vulnify, describe: Mapping[str, Describe], wait: Optional[dict] = None) -> Callable[[Any], Optional[bool]]:
    """A CrewAI ``before_tool_call`` hook that asks Vulnify before each listed tool runs.

        from crewai.hooks import register_before_tool_call_hook
        register_before_tool_call_hook(crewai_before_tool_call(vulnify, {"export_customers": describe_export}))

    Returns False (CrewAI skips the tool) when the action is not allowed; tools not in ``describe`` are left alone.
    The agent only sees CrewAI's generic "blocked by hook" text: use :func:`guard_crewai_tool` when the agent
    should read Vulnify's reasons.
    """

    def hook(context: Any) -> Optional[bool]:
        describe_tool = describe.get(getattr(context, "tool_name", ""))
        if describe_tool is None:
            return None
        blocked = _check_allowed(vulnify, describe_tool(dict(getattr(context, "tool_input", None) or {})), wait)
        return False if blocked else None

    return hook


def guard_crewai_tool(vulnify: Vulnify, tool: Any, describe: Describe, wait: Optional[dict] = None, on_blocked: str = "message") -> Any:
    """Guard a CrewAI tool instance (a ``BaseTool`` subclass or a ``@tool`` function) in place and return it.

    ``on_blocked="message"`` (default) makes the tool answer the block reason to the agent;
    ``"raise"`` raises :class:`VulnifyBlockedError`.
    """
    if on_blocked not in ("message", "raise"):
        raise ValueError("on_blocked must be 'message' or 'raise'")
    for attr in ("_run", "_arun"):
        original = getattr(tool, attr, None)
        if not callable(original):
            continue
        if attr == "_run":

            def run(*args: Any, __original: Callable[..., Any] = original, **kwargs: Any) -> Any:
                blocked = _check_allowed(vulnify, describe(dict(kwargs)), wait)
                if blocked:
                    if on_blocked == "raise":
                        raise blocked
                    return _blocked_message(blocked)
                return __original(*args, **kwargs)

            object.__setattr__(tool, attr, run)
        else:

            async def arun(*args: Any, __original: Callable[..., Any] = original, **kwargs: Any) -> Any:
                blocked = await asyncio.to_thread(_check_allowed, vulnify, describe(dict(kwargs)), wait)
                if blocked:
                    if on_blocked == "raise":
                        raise blocked
                    return _blocked_message(blocked)
                return await __original(*args, **kwargs)

            object.__setattr__(tool, attr, arun)
    return tool


# ---------------------------------------------------------------------------------------------------- LangGraph


def _tool_message(content: str, tool_call: Mapping[str, Any]) -> Any:
    try:
        from langchain_core.messages import ToolMessage  # type: ignore
    except ImportError:  # the adapter itself does not need LangChain
        return {"type": "tool", "content": content, "tool_call_id": tool_call.get("id"), "name": tool_call.get("name"), "status": "error"}
    return ToolMessage(content=content, tool_call_id=tool_call.get("id"), name=tool_call.get("name"), status="error")


def langgraph_tool_guard(vulnify: Vulnify, describe: Mapping[str, Describe], wait: Optional[dict] = None) -> Callable[[Any, Callable[[Any], Any]], Any]:
    """A ``wrap_tool_call`` for LangGraph's ``ToolNode`` (also usable as agent middleware ``wrap_tool_call``).

        ToolNode(tools, wrap_tool_call=langgraph_tool_guard(vulnify, {"export_customers": describe_export}))

    A call that is not allowed answers an error ``ToolMessage`` with Vulnify's reasons instead of running the tool,
    so the model sees why. Tools not in ``describe`` run unchanged.
    """

    def wrap(request: Any, execute: Callable[[Any], Any]) -> Any:
        tool_call = request.tool_call
        describe_tool = describe.get(tool_call.get("name", ""))
        if describe_tool is None:
            return execute(request)
        blocked = _check_allowed(vulnify, describe_tool(dict(tool_call.get("args") or {})), wait)
        return _tool_message(_blocked_message(blocked), tool_call) if blocked else execute(request)

    return wrap


def alanggraph_tool_guard(vulnify: Vulnify, describe: Mapping[str, Describe], wait: Optional[dict] = None) -> Callable[[Any, Callable[[Any], Any]], Any]:
    """Async variant for ``ToolNode(awrap_tool_call=...)``: the Vulnify check runs in a worker thread."""

    async def awrap(request: Any, execute: Callable[[Any], Any]) -> Any:
        tool_call = request.tool_call
        describe_tool = describe.get(tool_call.get("name", ""))
        if describe_tool is None:
            return await execute(request)
        blocked = await asyncio.to_thread(_check_allowed, vulnify, describe_tool(dict(tool_call.get("args") or {})), wait)
        return _tool_message(_blocked_message(blocked), tool_call) if blocked else await execute(request)

    return awrap
