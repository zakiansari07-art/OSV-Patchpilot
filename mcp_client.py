"""Generic MCP stdio client and policy gateway for the configured servers."""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
from contextlib import AsyncExitStack, closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from async_utils import run_async

logger = logging.getLogger(__name__)


class MCPCallError(RuntimeError):
    """A tool call failed after launching or contacting its MCP server."""

    def __init__(self, server: str, tool: str, detail: str, *, retryable: bool = False) -> None:
        self.server = server
        self.tool = tool
        self.retryable = retryable
        super().__init__(f"MCP {server}.{tool} failed: {detail}")


def _exception_details(error: BaseException) -> str:
    """Expose leaf errors hidden inside Python 3.11 ExceptionGroups."""
    children = getattr(error, "exceptions", None)
    if children:
        details = "; ".join(_exception_details(child) for child in children)
        return f"{type(error).__name__}: {details}"
    message = str(error).strip()
    return f"{type(error).__name__}" + (f": {message}" if message else "")


def default_state_db_path() -> Path:
    """Return a stable per-user database location outside target checkouts."""
    configured = os.getenv("AGENT_STATE_DB")
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.home() / ".vulnerability-patch-agent" / "state.sqlite3").resolve()


class SQLiteAuditLog:
    """Append-only audit records stored durably in the agent SQLite database."""
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path).expanduser().resolve()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection, connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS mcp_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                target_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK(outcome IN ('allowed', 'denied', 'error')),
                reason TEXT NOT NULL
            )""")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_mcp_audit_run ON mcp_audit(run_id, id)")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def record(self, run_id: str, server: str, tool: str, outcome: str, reason: str = "") -> int:
        if outcome not in {"allowed", "denied", "error"}:
            raise ValueError(f"Unsupported MCP audit outcome: {outcome}")
        timestamp = datetime.now(timezone.utc).isoformat()
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                "INSERT INTO mcp_audit(run_id, timestamp_utc, target_server, tool_name, outcome, reason) VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, timestamp, server, tool, outcome, reason),
            )
            return int(cursor.lastrowid)

    def finalize(self, event_id: int, outcome: str, reason: str = "") -> None:
        """Update a pre-authorized event after MCP execution completes."""
        if outcome not in {"allowed", "error"}:
            raise ValueError(f"Unsupported MCP audit outcome: {outcome}")
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "UPDATE mcp_audit SET outcome = ?, reason = ? WHERE id = ?",
                (outcome, reason, event_id),
            )

    def events_for_run(self, run_id: str) -> list[dict[str, str]]:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                "SELECT timestamp_utc, target_server, tool_name, outcome, reason FROM mcp_audit WHERE run_id = ? ORDER BY id",
                (run_id,),
            ).fetchall()
        return [{"timestamp": row["timestamp_utc"], "server": row["target_server"],
                 "tool": row["tool_name"], "outcome": row["outcome"], "reason": row["reason"]}
                for row in rows]


class MCPPolicyError(PermissionError):
    """Raised when an MCP request violates the local agent policy."""


class MCPPolicyProxy:
    """In-process MCP gateway enforcing a narrow tool and path policy.

    LangGraph receives this proxy rather than a raw MCP client, so every tool
    request made by the agent passes through authorization and safe auditing.
    The audit deliberately excludes arguments because they may contain source.
    """
    ALLOWED = {
        "filesystem": {"read_text_file", "read_multiple_files", "directory_tree", "write_file"},
        "git": {"git_status", "git_create_branch", "git_add", "git_commit"},
    }

    def __init__(self, client: Any, *, database_path: str | Path | None = None, run_id: str = "default") -> None:
        self.client = client
        self.audit_log = SQLiteAuditLog(database_path or default_state_db_path())
        self.run_id = run_id

    @staticmethod
    def _root(repo_path: str) -> Path:
        root = Path(repo_path).expanduser().resolve()
        if not root.is_dir():
            raise MCPPolicyError("MCP repository path must be an existing directory")
        return root

    @staticmethod
    def _safe_relative(root: Path, path: str, *, allow_root: bool = False) -> str:
        candidate = Path(path)
        resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
        if resolved != root and root not in resolved.parents:
            raise MCPPolicyError("Filesystem MCP path escapes the target repository")
        if resolved == root and not allow_root:
            raise MCPPolicyError("Filesystem MCP file operations must target a file inside the repository")
        relative = resolved.relative_to(root).as_posix() if resolved != root else "."
        parts = {part.lower() for part in Path(relative).parts}
        name = Path(relative).name.lower()
        secret_name = re.compile(r"(?i)(?:^|[._-])(?:credentials?|secrets?|tokens?|passwords?|private[_-]?keys?|api[_-]?keys?)(?:[._-]|$)")
        if (parts & {".env", ".npmrc", ".pypirc", "credentials", "secrets", "id_rsa", "id_ed25519"}
                or name.startswith(".env") or Path(name).suffix in {".pem", ".key", ".p12", ".pfx", ".keystore"}
                or any(secret_name.search(part) for part in parts)):
            raise MCPPolicyError("Filesystem MCP access to likely secret files is blocked")
        return relative

    def _record(self, server: str, tool: str, outcome: str, reason: str = "") -> int:
        event_id = self.audit_log.record(self.run_id, server, tool, outcome, reason)
        logger.info("MCP policy %s: %s.%s%s", outcome, server, tool, f" ({reason})" if reason else "")
        return event_id

    def _authorize(self, server: str, tool: str, repo_path: str, arguments: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
        root = self._root(repo_path)
        if tool not in self.ALLOWED.get(server, set()):
            raise MCPPolicyError(f"MCP tool is not allowlisted: {server}.{tool}")
        args = dict(arguments)
        if server == "filesystem":
            if tool == "read_multiple_files":
                paths = args.get("paths")
                if not isinstance(paths, list) or not paths:
                    raise MCPPolicyError("Filesystem MCP request requires a non-empty paths list")
                args["paths"] = [
                    str(root / self._safe_relative(root, str(path))) for path in paths
                ]
            else:
                if "path" not in args:
                    raise MCPPolicyError("Filesystem MCP request is missing its path")
                args["path"] = str(root / self._safe_relative(root, str(args["path"]), allow_root=tool == "directory_tree"))
        else:
            requested_root = Path(str(args.get("repo_path", repo_path))).expanduser().resolve()
            if requested_root != root:
                raise MCPPolicyError("Git MCP request must target the selected repository")
            args["repo_path"] = str(root)
            if tool == "git_create_branch":
                branch = str(args.get("branch_name", ""))
                if not re.fullmatch(r"security/[A-Za-z0-9._/-]+", branch) or ".." in branch.split("/"):
                    raise MCPPolicyError("Git MCP may create only safe security/* branches")
            elif tool == "git_add":
                files = args.get("files")
                if not isinstance(files, list) or not files:
                    raise MCPPolicyError("Git MCP staging requires an explicit non-empty file list")
                args["files"] = [self._safe_relative(root, str(item)) for item in files]
            elif tool == "git_commit" and not str(args.get("message", "")).startswith("fix(security):"):
                raise MCPPolicyError("Git MCP commit message must use the fix(security): prefix")
        return root, args

    def call(self, server: str, repo_path: str, tool: str, arguments: dict[str, Any]) -> str:
        try:
            root, safe_args = self._authorize(server, tool, repo_path, arguments)
        except MCPPolicyError as exc:
            self._record(server, tool, "denied", str(exc))
            raise
        event_id = self._record(server, tool, "allowed")
        try:
            result = self.client.call(server, str(root), tool, safe_args)
        except Exception as exc:
            # Error messages may echo arguments/source; retain only the class.
            self.audit_log.finalize(event_id, "error", type(exc).__name__)
            raise
        return result


class MCPClient:
    """Launches MCP servers from mcp_config.json for each tool operation.

    Keeping each operation self-contained guarantees subprocess cleanup even
    when LangGraph retries a node after an exception.
    """
    def __init__(self, config_path: str | Path | None = None) -> None:
        self.config_path = Path(config_path or Path(__file__).with_name("mcp_config.json"))

    def _config(self, server: str, repo_path: str) -> dict[str, Any]:
        try:
            config = json.loads(self.config_path.read_text(encoding="utf-8"))
            spec = config["mcpServers"][server]
        except (OSError, KeyError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Unable to load MCP server configuration for {server}: {exc}") from exc
        return {**spec, "args": [str(arg).replace("{repo_path}", str(Path(repo_path).resolve())) for arg in spec["args"]]}

    async def _call(self, server: str, repo_path: str, tool: str, arguments: dict[str, Any]) -> str:
        spec = self._config(server, repo_path)
        params = StdioServerParameters(command=spec["command"], args=spec["args"], env=os.environ.copy())
        try:
            async with AsyncExitStack() as stack:
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                result = await session.call_tool(tool, arguments=arguments)
                if result.isError:
                    raise MCPCallError(
                        server, tool, self._content_text(result.content), retryable=False,
                    )
                if result.structuredContent:
                    # The filesystem server may expose read_text_file as
                    # structured content ({"content": "..."}). Returning
                    # JSON here makes downstream parsers and patch edits
                    # operate on the wrapper instead of the actual file.
                    if server == "filesystem" and tool in {"read_text_file", "read_multiple_files"}:
                        structured = result.structuredContent
                        if isinstance(structured, dict):
                            for key in ("content", "text"):
                                value = structured.get(key)
                                if isinstance(value, str):
                                    return value
                        if isinstance(structured, str):
                            return structured
                    return json.dumps(result.structuredContent, ensure_ascii=False)
                return self._content_text(result.content)
        except MCPCallError:
            raise
        except Exception as exc:
            raise MCPCallError(server, tool, _exception_details(exc), retryable=True) from exc

    @staticmethod
    def _content_text(content: list[Any]) -> str:
        return "\n".join(str(getattr(item, "text", item)) for item in content)

    def call(self, server: str, repo_path: str, tool: str, arguments: dict[str, Any]) -> str:
        """Run an MCP request, retrying one transient server startup failure."""
        for attempt in range(2):
            try:
                return run_async(self._call(server, repo_path, tool, arguments))
            except MCPCallError as exc:
                if not exc.retryable or attempt == 1:
                    raise
                logger.warning("Transient MCP %s.%s failure; retrying once: %s", server, tool, exc)
                time.sleep(0.25)
        raise AssertionError("unreachable")
