"""LangGraph + Vulnify: every tool call of the ToolNode is checked first.

pip install langgraph langchain-openai  (plus this package: pip install -e .)
"""

import os

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

from vulnify import Vulnify
from vulnify.adapters import langgraph_tool_guard

# Production API by default. Local: VULNIFY_BASE_URL=http://localhost:3000
vulnify = Vulnify(api_key=os.environ["VULNIFY_API_KEY"])


@tool
def delete_ticket(ticket_id: str) -> str:
    """Delete a support ticket."""
    return f"Deleted {ticket_id}"


@tool
def search_docs(query: str) -> str:
    """Search the public documentation."""
    return f"Docs about {query}"


tools = [delete_ticket, search_docs]
# Only delete_ticket is checked; a blocked call becomes an error ToolMessage with Vulnify's reasons.
guard = langgraph_tool_guard(
    vulnify,
    {"delete_ticket": lambda args: {"agent": "SupportBot", "action": "DELETE_DATA", "resource": "Support Tickets", "records_affected": 1}},
)

model = ChatOpenAI(model="gpt-4o-mini").bind_tools(tools)


def call_model(state: MessagesState):
    return {"messages": [model.invoke(state["messages"])]}


graph = StateGraph(MessagesState)
graph.add_node("model", call_model)
graph.add_node("tools", ToolNode(tools, wrap_tool_call=guard))
graph.add_edge(START, "model")
graph.add_conditional_edges("model", tools_condition)
graph.add_edge("tools", "model")
app = graph.compile()

if __name__ == "__main__":
    result = app.invoke({"messages": [("user", "Delete ticket T-123")]})
    print(result["messages"][-1].content)
