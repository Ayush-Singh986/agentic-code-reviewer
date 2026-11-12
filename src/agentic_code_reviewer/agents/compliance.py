"""Compliance & regulation checker agent.

Checks for compliance with GDPR, HIPAA, SOC 2, and PCI-DSS: detects PII
handling without audit trails or consent mechanisms, PHI data patterns,
missing encryption markers, payment card data handling, and inadequate
access control or logging.
"""

from __future__ import annotations

from agentic_code_reviewer.agents.base import AgentRun, AnalysisAgent
from agentic_code_reviewer.orchestration.state import ReviewState


class ComplianceAgent(AnalysisAgent):
    name = "compliance"
    category = "compliance"
    prompt_version = "v1"

    def run(self, state: ReviewState, diff_text: str) -> AgentRun:
        return self._collect(state, diff_text)