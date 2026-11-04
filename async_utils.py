"""Small bridge for running async SDK calls from synchronous graph nodes."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Coroutine


def run_async(coroutine: Coroutine[Any, Any, Any]) -> Any:
    """Run a coroutine safely, including when called from an active event loop.

    Synchronous LangGraph invocation is the agent's public entry point. If an
    embedding application calls it from an async context, execute the SDK
    coroutine on a worker thread instead of nesting ``asyncio.run``.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="agent-async") as executor:
        return executor.submit(asyncio.run, coroutine).result()
