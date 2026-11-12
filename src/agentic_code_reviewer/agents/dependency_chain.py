"""Dependency chain analysis agent.

Analyzes transitive dependency graphs to identify security vulnerabilities
(CVE-style pattern matching, known vulnerable packages, unpinned/broad ranges
in pyproject.toml / requirements.txt / package-lock.json), and flags cloud-cost
risks from performance-related dependency changes (e.g. adding a heavy
serialization library).
"""

from __future__ import annotations

from agentic_code_reviewer.agents.base import AgentRun, AnalysisAgent
from agentic_code_reviewer.orchestration.state import ReviewState


class DependencyChainAgent(AnalysisAgent):
    name = "dependency_chain"
    category = "dependency_chain"
    prompt_version = "v1"

    def run(self, state: ReviewState, diff_text: str) -> AgentRun:
        return self._collect(state, diff_text)