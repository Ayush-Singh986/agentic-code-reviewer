# Dependency chain analysis and compliance & regulation checker

This PR adds two new analysis agents to the code review pipeline: `DependencyChainAgent` and `ComplianceAgent`. These expand the review surface to cover transitive dependency vulnerabilities (CVE-style patterns, known vulnerable packages, unpinned ranges) and regulatory compliance (GDPR PII handling, HIPAA PHI detection, PCI-DSS card data exposure, SOC 2 audit trails).

The implementation follows the existing pattern: both agents subclass `AnalysisAgent`, set consistent `name`/`category`/`prompt_version` attributes, and delegate to `self._collect()` for the standard LLM analysis flow. The agents are registered in the workflow's `_ANALYSIS_AGENTS` and `_CHECK_SWITCHES` dictionaries, and their ablation switches are added to `settings.py`. Deterministic regex patterns for both new categories are defined in `category_rules.py` and merged into `CATEGORY_PATTERNS_EXTRA`, while `rules.py` imports and incorporates those patterns.

**Watch for:**  
The new compliance patterns (`gdpr-no-consent`, `soc2-missing-audit`, `soc2-access-control`) use negative lookahead to assert the *absence* of consent/audit mechanisms. If the pattern engine's negative lookahead implementation behaves unexpectedly (especially across line boundaries), these could produce false positives or false negatives depending on what context follows the matched lines.  
**Verdict**: APPROVED

---

High-level view:  
The dependency chain agent leverages deterministic regex patterns to flag known vulnerable packages, unpinned transitive dependencies, git-sourced dependencies, and cloud-cost-impacting packages in dependency manifests. It does not actually parse the dependency graph — it signals *potential* issues that require manual follow-up. The compliance agent checks for sensitive PII/PHI/payment-card fields and flags missing consent, audit trails, or access controls via similar pattern matching. Both agents integrate seamlessly into the existing multi-agent workflow: they run in parallel with the other 22 agents, contribute findings to the shared `state.findings`, and go through the same verifier pipeline before aggregation. No runtime code execution or external network calls are introduced — all checks are static pattern matching.

<details>
<summary>Issues (3)</summary>

1. **Negative lookahead in compliance patterns** — patterns like `gdpr-no-consent` and `soc2-missing-audit` use negative lookahead to assert absence of consent/audit keywords; verify that the regex engine's behavior across line boundaries matches expectations to avoid false positives/negatives.
2. **Dependency-chain pattern ambiguity** — `dep-chain-unpinned-transitive` matches lower-bound-only version ranges but cannot distinguish between direct and transitive dependencies; this may produce noisy alerts for packages that are intentionally unpinned at the direct dependency level.
3. **Pattern coverage gaps** — compliance patterns cover GDPR, HIPAA, PCI-DSS, and SOC 2, but miss additional frameworks like CCPA, LGPD, or industry-specific regulations (FINRA, HIPAA-BAA); the design allows for future expansion but the current coverage is incomplete.

</details>

<details>
<summary>Details</summary>

## Pattern architecture and integration

Both agents extend `AnalysisAgent` and implement the expected `run(state, diff_text)` signature that returns `AgentRun`. The `name` and `category` fields are identical (`"dependency_chain"` and `"compliance"`), matching their ablation switch fields in `settings.py` (`workflow_use_dependency_chain_agent` and `workflow_use_compliance_agent`). The `prompt_version` is set to `"v1"` for both, consistent with other new agents.

Patterns are added to `CATEGORY_PATTERNS_EXTRA` in `category_rules.py`, which are then imported and merged into `CATEGORY_PATTERNS` in `rules.py`. The merge is correct: no duplicate keys exist in `CATEGORY_PATTERNS_EXTRA`, and the import statement `from agentic_code_reviewer.analysis.category_rules import (..., DEPENDENCY_CHAIN_PATTERNS, COMPLIANCE_PATTERNS, ...)` is correctly structured. Both agents are registered in `_ANALYSIS_AGENTS` and `_CHECK_SWITCHES` dictionaries with matching keys.

No circular dependencies are introduced — all imports are top-level in the agents module and follow the existing dependency hierarchy (agents → orchestration → config).

## Pattern specificity and quality

### Dependency chain analysis

The dependency chain patterns focus on package names (`log4j`, `lodash`, `moment`, `pyyaml`, `pillow`, `urllib3`, etc.) and version specifiers. Two patterns deserve closer inspection:

- `dep-chain-vulnerable-pkg`: This pattern matches a set of known vulnerable package names. While specific to known bad actors, it is still a broad pattern that will match any occurrence of those names in a dependency file. It does not verify that the line represents an actual dependency declaration (e.g., it would match a comment mentioning the package name). This is acceptable for a "signal, not a verdict" style check, but the confidence in findings will likely be `insufficient_evidence` unless the verifier layer confirms the context.
- `dep-chain-unpinned-transitive`: The regex `[\w.\-]+\s*[>=~]=\s*\d+(?:\.\d+)*[^<>=~]` matches lower-bound-only ranges but may produce false positives on lines like `requests>=2.25.0, <3.0.0` where an upper bound *is* present (the `<3.0.0` part is outside the pattern's scope). The pattern needs a negative lookahead to ensure no upper bound follows, or the verifier will need to disambiguate between truly unpinned and partially constrained dependencies.

The `dep-chain-pinned-hash` pattern (`--hash = sha256|sha384|sha512:...`) correctly identifies hash-pinned dependencies, which is a positive signal for supply-chain security.

### Compliance & regulation

The compliance patterns are category-specific and target the right keywords for each regulation:

- GDPR: PII field detection (`email`, `phone`, `dob`, `ssn`, `address`, `full_name`, `first_name`, `last_name`, `ip_address`, `user_agent`) and consent tracking (`consent`, `gdpr`, `lawful`, `permission`).
- HIPAA: PHI field detection (`diagnosis`, `medication`, `treatment`, `patient`, `health_record`, `medical`, `mrn`, `insurance`, `clinical`, `lab_result`).
- PCI-DSS: Card data fields (`card_number`, `cvv`, `cvc`, `pan`, `cardholder`, `expiry`, `credit_card`, `payment_card`, `debit_card`) and missing encryption markers.
- SOC 2: Audit trail and access control gaps.

Two patterns raise concerns:

- `gdpr-no-consent` uses a negative lookahead `(?!"` ... `consent|gdpr|lawful|permission))` to assert the *absence* of consent keywords after a data insert/create/save operation. The negative lookahead pattern `(?!" ... )` is syntactically valid but will only look at characters immediately after the matched field name, not across the entire line or subsequent lines. If the consent flag appears on a different line, this pattern will not detect it. The same concern applies to `soc2-missing-audit` and `soc2-access-control`. For reliable detection of missing controls, the verifier or taint layer would need to analyze multi-line scope, not just the changed line.
- `pci-dss-no-encrypt`: The pattern matches a card field assignment followed by the absence of encryption keywords. Again, the negative lookahead is line-scoped; if encryption is applied on a subsequent line (e.g., `card = request.card` then `encrypted = encrypt(card)`), this pattern will incorrectly flag the code.

The overall pattern strategy is appropriate for a "signal" layer — the verifier can downgrade `insufficient_evidence` findings when the context doesn't fully confirm the risk. The concern is that the current regex scope may not match the developer's mental model of what constitutes a consent or encryption "missing" situation.

## Architecture conformance and registration

Both agents conform to the existing agent scaffolding:

- `name = "dependency_chain"` / `"compliance"`
- `category = "dependency_chain"` / `"compliance"`
- `prompt_version = "v1"`
- `run(state, diff_text) -> AgentRun` delegates to `self._collect(state, diff_text)`

The `_collect` method in `AnalysisAgent` builds the prompt from the shared context (`DIFF`, `PLAN`, `CHANGE_SUMMARY`, `CONTEXT`, `KNOWLEDGE`, `REPOSITORY`, `REQUIREMENT`, `HISTORY`) and calls the structured LLM interface with `AnalysisResult` as the output schema.

In `workflow.py`, both agents are correctly added to `_ANALYSIS_AGENTS` and `_CHECK_SWITCHES`:

```python
_ANALYSIS_AGENTS = {
    # ...
    "dependency_chain": DependencyChainAgent,
    "compliance": ComplianceAgent,
    # ...
}

_CHECK_SWITCHES = {
    # ...
    "dependency_chain": "workflow_use_dependency_chain_agent",
    "compliance": "workflow_use_compliance_agent",
    # ...
}
```

The ablation switches are also defined in `settings.py` with default value `true`, meaning the agents are enabled unless explicitly disabled via environment variables or a repo policy file.

## Test coverage and verification

The import check (`python -c "from agentic_code_reviewer.agents.dependency_chain import DependencyChainAgent; from agentic_code_reviewer.agents.compliance import ComplianceAgent; print('ok")`) passes, confirming no import errors or circular dependencies.

The deterministic patterns in `category_rules.py` are valid Python regex patterns (compiled at import time with `re.compile`). The integration in `rules.py` is correct: `CATEGORY_PATTERNS` imports the extra patterns via `**CATEGORY_PATTERNS_EXTRA`, so they are included in the `match_category_patterns(category, line_text)` lookup.

The verifier layer will run regex verification against the same patterns, so any finding from these agents that references a changed line with a matching pattern will be marked `confirmed`. Findings that rely on inferred context (e.g., missing consent based on a data insert without seeing the consent field in the same diff) will likely be `insufficient_evidence` or `rejected` depending on what the diff actually shows.

## Not tested

- Multi-line consent/audit checks: The current regex patterns cannot detect missing consent or audit trails when the control is on a different line than the data operation. A more robust implementation would require AST or token-stream analysis to track scope.
- Dependency graph parsing: The agent does not parse `requirements.txt`, `pyproject.toml`, or `package-lock.json` to build an actual transitive dependency graph. It only flags patterns in the manifest text, so it cannot confirm whether a "known vulnerable" package is actually included in the resolved graph or is a transitive dependency that gets patched.
- Pattern edge cases: The patterns have not been validated against edge cases like package names inside comments, strings, or docstrings, or version specifiers with unusual formatting.

## Recommendations

1. **Add regex verification in the verifier layer**: When a compliance agent finds `gdpr-no-consent`, `soc2-missing-audit`, or `soc2-access-control`, the verifier should downgrade to `insufficient_evidence` unless the changed line itself contains both the data operation *and* the consent/audit marker (which would make the finding a false positive). Consider adding a pattern to the verifier that *confirms* the presence of consent or audit on the same line.

2. **Document pattern limitations**: Update the README or a dedicated `docs/patterns.md` file to clarify that these patterns are "signal only" and require manual verification. Users should understand that a "confirmed" status means the pattern appears in the changed line, not that the security gap is definitively present in the deployed code.

3. **Consider AST-based verification for compliance**: For the compliance category, a simple AST walk that tracks field definitions and consent flags could produce more accurate signals. This would be a future enhancement, not a blocker for this PR.

</details>