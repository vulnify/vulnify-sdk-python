"""Framework adapters.

Duck-typed on purpose: this package does not import CrewAI, LangGraph, LangChain, the OpenAI Agents SDK,
or the MCP SDK, so it works with whichever version you use. Install a framework with an extra
(``vulnify[langchain]``, ``vulnify[openai-agents]``, ``vulnify[mcp]``) when you want that package; the
core install stays dependency-free. Every adapter takes a ``describe`` callable that maps the tool's
arguments to the keyword arguments of :meth:`Vulnify.check` (agent, action, resource, destination,
records_affected, content, ...). Checks go through :meth:`Vulnify.guard`, so ``final_decision`` is the
outcome that allows or blocks a call.

The npm SDK's Vercel AI SDK helper has no Python counterpart and is not included.
"""

from __future__ import annotations

import asyncio
import copy
import functools
import inspect
import json
from typing import Any, Callable, Dict, Mapping, Optional

from .client import Vulnify, VulnifyBlockedError

Describe = Callable[[Dict[str, Any]], Dict[str, Any]]


def _blocked_message(err: VulnifyBlockedError) -> str:
    return str(err)


def _reject_or_message(err: VulnifyBlockedError, on_blocked: str) -> str:
    if on_blocked == "raise":
        raise err
    return _blocked_message(err)


def _require_on_blocked(on_blocked: str) -> None:
    if on_blocked not in ("message", "raise"):
        raise ValueError("on_blocked must be 'message' or 'raise'")


def _describe_args(value: Any) -> Dict[str, Any]:
    """Normalize a tool input to the dict ``describe`` receives."""
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"input": value}
        if isinstance(parsed, dict):
            return parsed
        return {"input": parsed}
    if isinstance(value, Mapping):
        return dict(value)
    return {"input": value}


def _set_attr(obj: Any, name: str, value: Any) -> None:
    try:
        setattr(obj, name, value)
    except (AttributeError, TypeError, ValueError):
        object.__setattr__(obj, name, value)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


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


# ---------------------------------------------------------------------------------------------------- LangChain


def guard_langchain_tool(
    vulnify: Vulnify, tool: Any, describe: Describe, wait: Optional[dict] = None, on_blocked: str = "message"
) -> Any:
    """Guard a LangChain tool in place and return it.

    A ``BaseTool`` is guarded on ``_run`` / ``_arun``, so ``invoke``, ``ainvoke``, ``run``, and ``arun``
    check once. ``describe`` receives the bound tool arguments. A duck-typed tool that only implements
    ``invoke``, ``ainvoke``, ``run``, ``arun``, or ``call`` is guarded on those methods instead, and
    ``describe`` receives the first argument (a JSON object, a mapping, or ``{"input": value}``).

    ``on_blocked="message"`` (default) returns Vulnify's reasons to the caller. ``"raise"`` raises
    :class:`VulnifyBlockedError`, which is what the npm helper does.

        tool = guard_langchain_tool(vulnify, export_tool, describe_export)
    """
    _require_on_blocked(on_blocked)
    if callable(getattr(tool, "_run", None)) or callable(getattr(tool, "_arun", None)):
        _guard_run_pair(tool, vulnify, describe, wait, on_blocked)
        return tool

    wrapped = False
    for attr in ("invoke", "ainvoke", "run", "arun", "call"):
        original = getattr(tool, attr, None)
        if not callable(original):
            continue
        wrapped = True
        if asyncio.iscoroutinefunction(original):

            async def method(*args: Any, __original: Callable[..., Any] = original, **kwargs: Any) -> Any:
                blocked = await asyncio.to_thread(_check_allowed, vulnify, describe(_surface_input(args, kwargs)), wait)
                if blocked:
                    return _reject_or_message(blocked, on_blocked)
                return await _maybe_await(__original(*args, **kwargs))

        else:

            def method(*args: Any, __original: Callable[..., Any] = original, **kwargs: Any) -> Any:
                blocked = _check_allowed(vulnify, describe(_surface_input(args, kwargs)), wait)
                if blocked:
                    return _reject_or_message(blocked, on_blocked)
                return __original(*args, **kwargs)

        _set_attr(tool, attr, method)
    if not wrapped:
        raise ValueError("guard_langchain_tool: expected _run, invoke, call, run, or an async variant")
    return tool


def _surface_input(args: tuple, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    if args:
        return _describe_args(args[0])
    for key in ("input", "tool_input"):
        if key in kwargs:
            return _describe_args(kwargs[key])
    return {key: value for key, value in kwargs.items() if key != "config"}


def _calls_name(fn: Callable[..., Any], name: str) -> bool:
    code = getattr(fn, "__code__", None)
    if code is None:
        code = getattr(getattr(fn, "__func__", None), "__code__", None)
    return code is not None and name in code.co_names


def _guard_run_pair(tool: Any, vulnify: Vulnify, describe: Describe, wait: Optional[dict], on_blocked: str) -> None:
    """Guard ``_run`` and ``_arun`` once each.

    LangChain's default ``_arun`` calls ``self._run``. Wrapping both would ask Vulnify twice, so an
    ``_arun`` that already delegates to ``_run`` is left to that check.
    """
    run = getattr(tool, "_run", None)
    arun = getattr(tool, "_arun", None)
    if callable(run):

        def wrapped_run(*args: Any, __original: Callable[..., Any] = run, **kwargs: Any) -> Any:
            blocked = _check_allowed(vulnify, describe(_bound_args(__original, args, kwargs)), wait)
            if blocked:
                return _reject_or_message(blocked, on_blocked)
            return __original(*args, **kwargs)

        _set_attr(tool, "_run", wrapped_run)
    if callable(arun) and not (callable(run) and _calls_name(arun, "_run")):

        async def wrapped_arun(*args: Any, __original: Callable[..., Any] = arun, **kwargs: Any) -> Any:
            blocked = await asyncio.to_thread(_check_allowed, vulnify, describe(_bound_args(__original, args, kwargs)), wait)
            if blocked:
                return _reject_or_message(blocked, on_blocked)
            return await _maybe_await(__original(*args, **kwargs))

        _set_attr(tool, "_arun", wrapped_arun)


def _bound_args(fn: Callable[..., Any], args: tuple, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
    except (TypeError, ValueError):
        data = dict(kwargs)
        if args:
            data["input"] = args[0] if len(args) == 1 else list(args)
        return data
    return dict(bound.arguments)


# ----------------------------------------------------------------------------------------------- OpenAI Agents


def guard_openai_agents_tool(
    vulnify: Vulnify, tool: Any, describe: Describe, wait: Optional[dict] = None, on_blocked: str = "message"
) -> Any:
    """Guard an OpenAI Agents tool and return it.

    A Python ``FunctionTool`` is guarded on ``on_invoke_tool(ctx, input_json)``. The JSON string is
    parsed for ``describe``; the original callable still receives the raw string. A tool config with
    ``execute`` (or a JavaScript-shaped function tool with ``invoke``) is guarded the same way and
    returned as a new object, leaving the original callable in place.

    ``on_blocked="message"`` (default) returns the block text to the model. ``"raise"`` raises
    :class:`VulnifyBlockedError`.

        export_customers = guard_openai_agents_tool(vulnify, export_customers, describe_export)
    """
    _require_on_blocked(on_blocked)
    on_invoke = getattr(tool, "on_invoke_tool", None)
    if callable(on_invoke):

        async def on_invoke_tool(ctx: Any, tool_input: str, *rest: Any, __original: Callable[..., Any] = on_invoke) -> Any:
            blocked = await asyncio.to_thread(_check_allowed, vulnify, describe(_describe_args(tool_input)), wait)
            if blocked:
                return _reject_or_message(blocked, on_blocked)
            return await _maybe_await(__original(ctx, tool_input, *rest))

        _set_attr(tool, "on_invoke_tool", on_invoke_tool)
        return tool

    invoke = getattr(tool, "invoke", None)
    if callable(invoke) and getattr(tool, "type", None) == "function":

        async def invoke_tool(run_context: Any, tool_input: str, *rest: Any, __original: Callable[..., Any] = invoke) -> Any:
            blocked = await asyncio.to_thread(_check_allowed, vulnify, describe(_describe_args(tool_input)), wait)
            if blocked:
                return _reject_or_message(blocked, on_blocked)
            return await _maybe_await(__original(run_context, tool_input, *rest))

        return _replace_attr(tool, "invoke", invoke_tool)

    execute = _mapping_get(tool, "execute")
    if not callable(execute):
        raise ValueError(
            "guard_openai_agents_tool: expected a FunctionTool with on_invoke_tool, a function tool with invoke, or a tool config with execute"
        )

    async def execute_tool(tool_input: Any, *rest: Any, __original: Callable[..., Any] = execute) -> Any:
        blocked = await asyncio.to_thread(_check_allowed, vulnify, describe(_describe_args(tool_input)), wait)
        if blocked:
            return _reject_or_message(blocked, on_blocked)
        return await _maybe_await(__original(tool_input, *rest))

    return _replace_attr(tool, "execute", execute_tool)


def _mapping_get(tool: Any, name: str) -> Any:
    if isinstance(tool, Mapping):
        return tool.get(name)
    return getattr(tool, name, None)


def _replace_attr(tool: Any, name: str, value: Any) -> Any:
    """Return a shallow copy with one attribute replaced, so the original tool keeps its callable."""
    if isinstance(tool, Mapping):
        copied = dict(tool)
        copied[name] = value
        return copied
    try:
        clone = copy.copy(tool)
    except (TypeError, AttributeError):
        _set_attr(tool, name, value)
        return tool
    _set_attr(clone, name, value)
    return clone


# ----------------------------------------------------------------------------------------------------------- MCP


def _mcp_error_result(message: str) -> Any:
    """An MCP tool error. Uses ``CallToolResult`` when the mcp extra is installed."""
    try:
        from mcp.types import CallToolResult, TextContent  # type: ignore
    except ImportError:
        return {"isError": True, "content": [{"type": "text", "text": message}]}
    return CallToolResult(content=[TextContent(type="text", text=message)], is_error=True)


def guard_mcp_handler(
    vulnify: Vulnify, describe: Describe, handler: Callable[..., Any], wait: Optional[dict] = None
) -> Callable[..., Any]:
    """Wrap an MCP server tool function. A blocked call returns an MCP error result and does not raise.

    ``MCPServer`` (mcp 2, formerly FastMCP) calls the tool with keyword arguments, and those keywords
    are what ``describe`` sees. A handler written like the npm SDK, ``handler(args, extra)``, is also
    accepted: ``describe`` sees the mapping in the first argument, and both arguments are forwarded.

    Register the wrapper itself (the server keeps the function it was given). Other exceptions propagate.

        async def export_customers(rows: int) -> str:
            return f"exported {rows}"

        mcp.tool()(guard_mcp_handler(vulnify, describe_export, export_customers))
    """

    @functools.wraps(handler)
    async def wrapped(*args: Any, **kwargs: Any) -> Any:
        blocked = await asyncio.to_thread(_check_allowed, vulnify, describe(_mcp_handler_args(args, kwargs)), wait)
        if blocked:
            return _mcp_error_result(_blocked_message(blocked))
        return await _maybe_await(handler(*args, **kwargs))

    return wrapped


def _mcp_handler_args(args: tuple, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    if kwargs and not args:
        return dict(kwargs)
    if args and isinstance(args[0], Mapping):
        return dict(args[0])
    if len(args) == 1:
        return {"input": args[0]}
    if args:
        return {"args": list(args)}
    return dict(kwargs)


def guard_mcp_client(
    vulnify: Vulnify, session: Any, describe: Mapping[str, Describe], wait: Optional[dict] = None
) -> Any:
    """Guard ``session.call_tool`` in place and return the session.

    Tools named in ``describe`` are checked before the request is sent. A blocked call returns an MCP
    error result and does not call the server. Tools that are not listed are forwarded unchanged.

        session = guard_mcp_client(vulnify, session, {"export_customers": describe_export})
        result = await session.call_tool("export_customers", {"rows": 10})
    """
    original = session.call_tool

    async def call_tool(name: str, arguments: Optional[Mapping[str, Any]] = None, *args: Any, **kwargs: Any) -> Any:
        describe_tool = describe.get(name)
        if describe_tool is None:
            return await _maybe_await(original(name, arguments, *args, **kwargs))
        blocked = await asyncio.to_thread(
            _check_allowed, vulnify, describe_tool(dict(arguments or {})), wait
        )
        if blocked:
            return _mcp_error_result(_blocked_message(blocked))
        return await _maybe_await(original(name, arguments, *args, **kwargs))

    _set_attr(session, "call_tool", call_tool)
    return session
