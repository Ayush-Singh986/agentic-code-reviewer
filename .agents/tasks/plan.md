# Implementation Plan

Add two new review agent categories to the agentic-code-reviewer project:

1. **Dependency Chain Analysis** (`dependency_chain.py`) — analyzes transitive dependency graphs to identify security vulnerabilities (CVE-style pattern matching, known vulnerable packages, unpinned/broad ranges in pyproject.toml / requirements.txt / package-lock.json), and flags cloud-cost risks from performance-related dependency changes (e.g. adding a heavy serialization library).

2. **Compliance & Regulation Checker** (`compliance.py`) — checks for compliance with GDPR, HIPAA, SOC 2, and PCI-DSS: detects PII handling without audit trails or consent mechanisms, PHI data patterns, missing encryption markers, payment card data handling, and inadequate access control or logging.

---

## Exploration Summary

- **Build/Test Commands**: `pytest` runs 462 tests; `ruff check src/ tests/` for lint; `mypy src/agentic_code_reviewer` for type checking.
- **Agent Pattern**: Subclass `AnalysisAgent`, set `name`, `category`, `prompt_version`, implement `run(self, state, diff_text) -> AgentRun`.
- **Pattern Registration**: Add deterministic regex patterns to `analysis/category_rules.py`, register in `analysis/rules.py`'s `CATEGORY_PATTERNS` dict.
- **Workflow Integration**: Add agents to `_ANALYSIS_AGENTS` and `_CHECK_SWITCHES` in `orchestration/workflow.py`.
- **Ablation Switches**: Add boolean fields to `config/settings.py`.
- **README Update**: Update review categories table around line 155–180 to reflect 25 total categories.

---

## Files to Create

- `src/agentic_code_reviewer/agents/dependency_chain.py`
- `src/agentic_code_reviewer/agents/compliance.py`

## Files to Modify

- `src/agentic_code_reviewer/analysis/category_rules.py`
- `src/agentic_code_reviewer/analysis/rules.py`
- `src/agentic_code_reviewer/orchestration/workflow.py`
- `src/agentic_code_reviewer/config/settings.py`
- `README.md`

---

## Implementation Steps

- [ ] 1. Create `dependency_chain.py` with `DependencyChainAgent` class.
      Subclass `AnalysisAgent`, set `name = "dependency_chain"`, `category = "dependency_chain"`, `prompt_version = "v1"`.
      Implement `run(self, state, diff_text) -> AgentRun` calling `self._collect(state, diff_text)`.
      Files: `src/agentic_code_reviewer/agents/dependency_chain.py`
      Verify: import test passes (see step 5 verification).

- [ ] 2. Create `compliance.py` with `ComplianceAgent` class.
      Subclass `AnalysisAgent`, set `name = "compliance"`, `category = "compliance"`, `prompt_version = "v1"`.
      Implement `run(self, state, diff_text) -> AgentRun` calling `self._collect(state, diff_text)`.
      Files: `src/agentic_code_reviewer/agents/compliance.py`
      Verify: import test passes (see step 5 verification).

- [ ] 3. Add deterministic patterns for `dependency_chain` and `compliance` to `category_rules.py`.
      Add `DEPENDENCY_CHAIN_PATTERNS` list with rules:
      - `"unpinned-requirements"` — matches bare package names in requirements.txt (`^[A-Za-z0-9_.\-]+$`)
      - `"broad-version-range"` — matches lower-bound-only versions (`[\w.\-]+\s*>=\s*\d+(?:\.\d+)*`)
      - `"npm-wildcard"` — matches `"*"` version in package-lock.json
      - `"npm-latest"` — matches `"latest"` version in package-lock.json
      Add `COMPLIANCE_PATTERNS` list with rules:
      - `"pii-in-log"` — matches logger usage of sensitive fields (password, api_key, secret, token, ssn, credit_card, email)
      - `"pii-in-exception"` — matches raise with sensitive fields
      - `"phi-detected"` — matches medical code patterns (ICD-10, CPT, LOINC)
      - `"pci-card-pattern"` — matches 16-digit card numbers (amex: 15 digits, others: 16)
      - `"missing-encryption"` — matches plaintext storage of sensitive fields without encryption markers
      - `"gdpr-consent-missing"` — matches user action without consent/audit-trail markers
      Append both to `CATEGORY_PATTERNS_EXTRA` dict.
      Files: `src/agentic_code_reviewer/analysis/category_rules.py`
      Verify: patterns compile without error (see step 5 verification).

- [ ] 4. Register new categories in `analysis/rules.py`.
      Import `DEPENDENCY_CHAIN_PATTERNS` and `COMPLIANCE_PATTERNS` from `category_rules`.
      Add `"dependency_chain": DEPENDENCY_CHAIN_PATTERNS` and `"compliance": COMPLIANCE_PATTERNS` to `CATEGORY_PATTERNS` dict.
      Files: `src/agentic_code_reviewer/analysis/rules.py`
      Verify: imports succeed without error (see step 5 verification).

- [ ] 5. Register agents and ablation switches in `workflow.py`.
      Add import lines:
      - `from agentic_code_reviewer.agents.dependency_chain import DependencyChainAgent`
      - `from agentic_code_reviewer.agents.compliance import ComplianceAgent`
      Add entries to `_ANALYSIS_AGENTS` dict:
      - `"dependency_chain": DependencyChainAgent`
      - `"compliance": ComplianceAgent`
      Add entries to `_CHECK_SWITCHES` dict:
      - `"dependency_chain": "workflow_use_dependency_chain_agent"`
      - `"compliance": "workflow_use_compliance_agent"`
      Files: `src/agentic_code_reviewer/orchestration/workflow.py`
      Verify: `pytest tests/orchestration/test_workflow.py -k "test_" --no-header -q` runs without import errors.

- [ ] 6. Add ablation switch fields to `config/settings.py`.
      Add two boolean fields after `workflow_use_resource_lifecycle_agent`:
      - `workflow_use_dependency_chain_agent: bool = Field(default=True, alias="WORKFLOW_USE_DEPENDENCY_CHAIN_AGENT")`
      - `workflow_use_compliance_agent: bool = Field(default=True, alias="WORKFLOW_USE_COMPLIANCE_AGENT")`
      Files: `src/agentic_code_reviewer/config/settings.py`
      Verify: Settings instantiation succeeds with new fields (`python -c "from agentic_code_reviewer.config.settings import Settings; s = Settings(LLM_PROVIDER='mock'); assert hasattr(s, 'workflow_use_dependency_chain_agent') and hasattr(s, 'workflow_use_compliance_agent')"`).

- [ ] 7. Update README review categories table to reflect 25 total categories.
      Update the architecture diagram comment from "22 analysis agents" to "24 analysis agents".
      Update the Repository Structure comment from "22 analysis agents" to "24 analysis agents".
      In the configuration reference table around line 550, add:
      - `WORKFLOW_USE_DEPENDENCY_CHAIN_AGENT` / `WORKFLOW_USE_COMPLIANCE_AGENT` | all `true` | ablation switches - disable individual categories
      Files: `README.md`
      Verify: Table syntax is valid (no markdown rendering errors).

---

## Verification Procedure

1. After steps 1–2: Verify new agent files exist and are syntactically correct:
   ```bash
   python -c "import sys; sys.path.insert(0, 'src'); from agentic_code_reviewer.agents.dependency_chain import DependencyChainAgent; from agentic_code_reviewer.agents.compliance import ComplianceAgent"
   ```

2. After step 3: Verify patterns compile:
   ```bash
   python -c "import sys; sys.path.insert(0, 'src'); from agentic_code_reviewer.analysis.category_rules import DEPENDENCY_CHAIN_PATTERNS, COMPLIANCE_PATTERNS; print(len(DEPENDENCY_CHAIN_PATTERNS), len(COMPLIANCE_PATTERNS))"
   ```

3. After step 4: Verify CATEGORY_PATTERNS dict includes new keys:
   ```bash
   python -c "import sys; sys.path.insert(0, 'src'); from agentic_code_reviewer.analysis.rules import CATEGORY_PATTERNS; assert 'dependency_chain' in CATEGORY_PATTERNS and 'compliance' in CATEGORY_PATTERNS"
   ```

4. After step 5: Verify imports and agent registration:
   ```bash
   python -c "import sys; sys.path.insert(0, 'src'); from agentic_code_reviewer.orchestration.workflow import _ANALYSIS_AGENTS, _CHECK_SWITCHES; assert 'dependency_chain' in _ANALYSIS_AGENTS and 'compliance' in _ANALYSIS_AGENTS; assert 'dependency_chain' in _CHECK_SWITCHES and 'compliance' in _CHECK_SWITCHES"
   ```

5. After step 6: Verify Settings class has new fields:
   ```bash
   python -c "import sys; sys.path.insert(0, 'src'); from agentic_code_reviewer.config.settings import Settings; s = Settings(LLM_PROVIDER='mock'); assert hasattr(s, 'workflow_use_dependency_chain_agent') and hasattr(s, 'workflow_use_compliance_agent')"
   ```

6. After README update: Run full test suite:
   ```bash
   pytest
   ```
   All 462 tests should pass.

---

## Ablation Switch Environment Variables

- `WORKFLOW_USE_DEPENDENCY_CHAIN_AGENT=false` — disable the dependency chain analysis agent.
- `WORKFLOW_USE_COMPLIANCE_AGENT=false` — disable the compliance & regulation checker agent.

---

## Notes

- No prompt templates are needed for this task — the base `AnalysisAgent._collect` uses the generic `analysis` prompt template. A future step can add category-specific prompts in `prompts/analysis/` if needed.
- Deterministic verification follows the same layered pattern (regex → AST → symbol → taint) used by other categories.
- The README table counts 25 categories total (22 original + 4 extra + 2 new = 25), matching the "24 analysis agents + 1 deterministic dead-code checker" description.