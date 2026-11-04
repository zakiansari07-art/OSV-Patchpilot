"""SQLite lifecycle helper for durable LangGraph checkpoints.

The MCP audit table shares the same database file, while its writes are managed
by SQLiteAuditLog and remain independent atomic transactions.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any


class SQLiteAgentPersistence:
    """Own a SQLite connection and LangGraph SqliteSaver for a CLI invocation."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path).expanduser().resolve()
        self._connection: sqlite3.Connection | None = None
        self.checkpointer: Any | None = None

    def __enter__(self) -> "SQLiteAgentPersistence":
        # LangGraph recommends strict msgpack deserialization for checkpoint
        # databases that may be tampered with. The agent state uses plain data.
        os.environ.setdefault("LANGGRAPH_STRICT_MSGPACK", "true")
        try:
            from langgraph.checkpoint.sqlite import SqliteSaver
        except ImportError as exc:
            raise RuntimeError(
                "SQLite graph persistence requires langgraph-checkpoint-sqlite; install requirements.txt"
            ) from exc
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.database_path, check_same_thread=False)
        self.checkpointer = SqliteSaver(self._connection)
        self.checkpointer.setup()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
            self.checkpointer = None

    def list_thread_ids(self) -> list[str]:
        """Return checkpoint thread IDs so the CLI can find pending approvals."""
        if self._connection is None:
            raise RuntimeError("Persistence must be open before listing checkpoint threads")
        table = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'checkpoints'"
        ).fetchone()
        if table is None:
            return []
        rows = self._connection.execute(
            "SELECT DISTINCT thread_id FROM checkpoints ORDER BY thread_id"
        ).fetchall()
        return [str(row[0]) for row in rows if row and row[0]]
