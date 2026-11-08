"""Offline unit tests for the AI travel agent's graph, tools, and email flow."""
from __future__ import annotations

import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from agents.agent import Agent


flights_module = importlib.import_module("agents.tools.flights_finder")
hotels_module = importlib.import_module("agents.tools.hotels_finder")
agent_module = importlib.import_module("agents.agent")


def test_exists_action_routes_tool_calls_to_tool_node():
    state = {"messages": [SimpleNamespace(tool_calls=[{"name": "flights_finder"}])]}

    assert Agent.exists_action(state) == "more_tools"


def test_exists_action_routes_final_answer_to_email_checkpoint():
    state = {"messages": [SimpleNamespace(tool_calls=[])]}

    assert Agent.exists_action(state) == "email_sender"


def test_model_node_adds_system_prompt_and_returns_model_message():
    expected = AIMessage(content="Here are some travel options.")
    model = Mock()
    model.invoke.return_value = expected
    agent = Agent.__new__(Agent)
    agent._tools_llm = model

    result = agent.call_tools_llm({"messages": [HumanMessage(content="Find a flight.")]})

    sent_messages = model.invoke.call_args.args[0]
    assert isinstance(sent_messages[0], SystemMessage)
    assert "travel agency" in sent_messages[0].content
    assert result == {"messages": [expected]}


def test_tool_node_dispatches_known_tools_and_returns_tool_messages():
    tool = Mock()
    tool.invoke.return_value = [{"flight": "Example Air"}]
    agent = Agent.__new__(Agent)
    agent._tools = {"flights_finder": tool}
    call = {"id": "call-1", "name": "flights_finder", "args": {"params": {"departure_airport": "SFO"}}}

    result = agent.invoke_tools({"messages": [SimpleNamespace(tool_calls=[call])]})

    tool.invoke.assert_called_once_with(call["args"])
    assert len(result["messages"]) == 1
    assert isinstance(result["messages"][0], ToolMessage)
    assert result["messages"][0].tool_call_id == "call-1"
    assert "Example Air" in result["messages"][0].content


def test_tool_node_returns_a_retry_message_for_unknown_tool():
    agent = Agent.__new__(Agent)
    agent._tools = {}
    call = {"id": "call-2", "name": "unknown_tool", "args": {}}

    result = agent.invoke_tools({"messages": [SimpleNamespace(tool_calls=[call])]})

    assert "bad tool name" in result["messages"][0].content


def test_flights_tool_maps_arguments_and_returns_search_results(monkeypatch):
    response = SimpleNamespace(data={"best_flights": [{"airline": "Example Air"}]})
    search = Mock(return_value=response)
    monkeypatch.setattr(flights_module.serpapi, "search", search, raising=False)

    result = flights_module.flights_finder.invoke({
        "params": {
            "departure_airport": "SFO",
            "arrival_airport": "LHR",
            "outbound_date": "2026-12-01",
            "return_date": "2026-12-10",
        },
    })

    assert result == [{"airline": "Example Air"}]
    search.assert_called_once()
    params = search.call_args.args[0]
    assert params["engine"] == "google_flights"
    assert params["departure_id"] == "SFO"
    assert params["arrival_id"] == "LHR"
    assert params["outbound_date"] == "2026-12-01"


def test_flights_tool_returns_provider_error_as_text(monkeypatch):
    monkeypatch.setattr(
        flights_module.serpapi, "search",
        Mock(side_effect=RuntimeError("provider unavailable")), raising=False,
    )

    result = flights_module.flights_finder.invoke({
        "params": {"departure_airport": "SFO", "arrival_airport": "LHR"},
    })

    assert "provider unavailable" in result


def test_hotels_tool_returns_at_most_five_properties(monkeypatch):
    properties = [{"name": f"Hotel {number}"} for number in range(7)]
    search = Mock(return_value=SimpleNamespace(data={"properties": properties}))
    monkeypatch.setattr(hotels_module.serpapi, "search", search, raising=False)

    result = hotels_module.hotels_finder.invoke({
        "params": {
            "q": "London",
            "check_in_date": "2026-12-01",
            "check_out_date": "2026-12-05",
        },
    })

    assert result == properties[:5]
    params = search.call_args.args[0]
    assert params["engine"] == "google_hotels"
    assert params["q"] == "London"
    assert params["check_in_date"] == "2026-12-01"


def test_hotels_tool_propagates_provider_errors(monkeypatch):
    monkeypatch.setattr(
        hotels_module.serpapi, "search",
        Mock(side_effect=RuntimeError("provider unavailable")), raising=False,
    )

    with pytest.raises(RuntimeError, match="provider unavailable"):
        hotels_module.hotels_finder.invoke({
            "params": {
                "q": "London",
                "check_in_date": "2026-12-01",
                "check_out_date": "2026-12-05",
            },
        })


def test_graph_pauses_before_email_delivery_without_calling_openai(monkeypatch, capsys):
    class FakeChatOpenAI:
        def __init__(self, *args, **kwargs):
            pass

        def bind_tools(self, _tools):
            return self

        def invoke(self, _messages):
            return AIMessage(content="A safe demo travel response.")

    monkeypatch.setattr(agent_module, "ChatOpenAI", FakeChatOpenAI)
    agent = Agent()
    config = {"configurable": {"thread_id": "offline-graph-test"}}

    agent.graph.invoke(
        {"messages": [HumanMessage(content="Plan a sample trip.")]}, config=config,
    )

    assert agent.graph.get_state(config).next == ("email_sender",)
    capsys.readouterr()


def test_email_sender_formats_and_sends_email(monkeypatch):
    sent = {}

    class FakeEmailModel:
        def __init__(self, *args, **kwargs):
            pass

        def invoke(self, _messages):
            return SimpleNamespace(content="<html><body>Trip plan</body></html>")

    class FakeMail:
        def __init__(self, **kwargs):
            sent["mail"] = kwargs

    class FakeSendGrid:
        def __init__(self, api_key):
            sent["api_key"] = api_key

        def send(self, mail):
            sent["sent_mail"] = mail
            return SimpleNamespace(status_code=202, body="accepted", headers={})

    monkeypatch.setattr(agent_module, "ChatOpenAI", FakeEmailModel)
    monkeypatch.setattr(agent_module, "Mail", FakeMail)
    monkeypatch.setattr(agent_module, "SendGridAPIClient", FakeSendGrid)
    monkeypatch.setenv("FROM_EMAIL", "sender@example.com")
    monkeypatch.setenv("TO_EMAIL", "traveler@example.com")
    monkeypatch.setenv("EMAIL_SUBJECT", "Sample trip")
    monkeypatch.setenv("SENDGRID_API_KEY", "test-key")
    agent = Agent.__new__(Agent)

    agent.email_sender({"messages": [HumanMessage(content="Trip details") ]})

    assert sent["api_key"] == "test-key"
    assert sent["mail"].get("from_email") == "sender@example.com"
    assert sent["mail"].get("to_emails") == "traveler@example.com"
    assert sent["mail"].get("subject") == "Sample trip"
    assert "Trip plan" in sent["mail"].get("html_content")
