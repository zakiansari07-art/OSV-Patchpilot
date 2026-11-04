from typing import TypedDict

from langgraph.graph import END, StateGraph

from persistence import SQLiteAgentPersistence


class CounterState(TypedDict, total=False):
    value: int
    finished: bool


def make_graph(checkpointer, *, pause_before_finish=False):
    builder = StateGraph(CounterState)
    builder.add_node("increment", lambda state: {"value": state.get("value", 0) + 1})
    builder.add_node("finish", lambda state: {"finished": state.get("value") == 2})
    builder.set_entry_point("increment")
    builder.add_edge("increment", "finish")
    builder.add_edge("finish", END)
    options = {"checkpointer": checkpointer}
    if pause_before_finish:
        options["interrupt_before"] = ["finish"]
    return builder.compile(**options)


def test_sqlite_checkpointer_resumes_a_paused_thread_after_reopen(tmp_path):
    database = tmp_path / "state.sqlite3"
    config = {"configurable": {"thread_id": "resume-demo"}}

    with SQLiteAgentPersistence(database) as persistence:
        paused_graph = make_graph(persistence.checkpointer, pause_before_finish=True)
        paused = paused_graph.invoke({"value": 1}, config=config)
        assert paused["value"] == 2
        assert paused_graph.get_state(config).next == ("finish",)
        assert persistence.list_thread_ids() == ["resume-demo"]

    with SQLiteAgentPersistence(database) as persistence:
        resumed_graph = make_graph(persistence.checkpointer)
        completed = resumed_graph.invoke(None, config=config)
        assert completed["finished"] is True
        assert resumed_graph.get_state(config).next == ()
