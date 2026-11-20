"""The review board: specialist agents run in parallel (LangGraph fan-out), then the moderator fans in."""

from __future__ import annotations

import operator
import time
from typing import Annotated, Callable, TypedDict

from langgraph.graph import END, START, StateGraph

from .agents import complexity, maintainability, security, testing
from .models import ChangedFile, Finding, Review, Severity
from .moderator import moderate

Agent = Callable[[list[ChangedFile]], tuple[list[Finding], str]]

DEFAULT_AGENTS: dict[str, Agent] = {
    security.NAME: security.run,
    complexity.NAME: complexity.run,
    testing.NAME: testing.run,
    maintainability.NAME: maintainability.run,
}


class BoardState(TypedDict, total=False):
    files: list[ChangedFile]
    findings: Annotated[list[Finding], operator.add]
    notes: Annotated[dict[str, str], operator.or_]
    timings_ms: Annotated[dict[str, float], operator.or_]
    review: Review


def build_board(agents: dict[str, Agent] | None = None, per_file_cap: int = 10, min_severity: Severity = Severity.INFO):
    agents = agents or DEFAULT_AGENTS
    g = StateGraph(BoardState)

    def make_node(name: str, fn: Agent):
        def node(state: BoardState) -> dict:
            started = time.perf_counter()
            try:
                found, note = fn(state["files"])
            except Exception as exc:  # one broken reviewer must not sink the whole review
                found, note = [], f"agent failed: {type(exc).__name__}: {exc}"
            return {"findings": found, "notes": {name: note}, "timings_ms": {name: round((time.perf_counter() - started) * 1000, 1)}}
        return node

    for name, fn in agents.items():
        g.add_node(name, make_node(name, fn))
        g.add_edge(START, name)  # fan-out: every specialist sees the same change set

    def moderator(state: BoardState) -> dict:
        return {"review": moderate(state["files"], state.get("findings", []), state.get("notes", {}), per_file_cap, min_severity)}

    g.add_node("moderator", moderator)
    for name in agents:
        g.add_edge(name, "moderator")  # fan-in: moderator runs once all specialists finish
    g.add_edge("moderator", END)
    return g.compile()


def review(files: list[ChangedFile], agents: dict[str, Agent] | None = None, per_file_cap: int = 10,
           min_severity: Severity = Severity.INFO) -> tuple[Review, dict[str, float]]:
    state = build_board(agents, per_file_cap, min_severity).invoke({"files": files, "findings": [], "notes": {}, "timings_ms": {}})
    return state["review"], state.get("timings_ms", {})
