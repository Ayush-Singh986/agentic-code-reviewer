"""Deterministic patterns for the six new review categories, plus the
SSRF / path-traversal additions to the security rule set.

These live in their own module so the core ``rules.py`` stays focused on the
original categories; ``CATEGORY_PATTERNS`` merges them at import time.
"""

from __future__ import annotations

import re
from re import Pattern

# ----------------------------------------------------------------------
# Security additions: SSRF + path traversal (spec section 5)
# ----------------------------------------------------------------------
SECURITY_PATTERNS_EXTRA: list[tuple[str, Pattern[str]]] = [
    # A dynamic URL/host variable handed to an HTTP client. The taint layer
    # decides whether the variable is attacker-controlled; this rule only
    # confirms the sink shape.
    (
        "ssrf-dynamic-url",
        re.compile(
            r"(requests|httpx|urllib|aiohttp|urlopen)\s*\.\s*"
            r"(get|post|put|delete|request|urlopen|ClientSession)\s*\("
            r"[^)]*\b(url|target|endpoint|host|addr|link|callback|next|redirect|uri)\b",
            re.IGNORECASE,
        ),
    ),
    # Private/loopback/cloud-metadata target combined with an HTTP client on
    # the same or next line  -  evidence of an SSRF reachable target.
    (
        "ssrf-private-target",
        re.compile(
            r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|"
            r"localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
            re.IGNORECASE,
        ),
    ),
    (
        "path-traversal-open",
        re.compile(
            r"\bopen\s*\(\s*(path|filepath|file_name|filename|target|dest|dst|out|src)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "path-traversal-send",
        re.compile(r"(send_file|send_from_directory|FileResponse|StaticFiles)\s*\(", re.IGNORECASE),
    ),
    (
        "path-traversal-shutil",
        re.compile(
            r"shutil\s*\.\s*(copy|move|rmtree|unpack_archive)\s*\([^)]*\b"
            r"(path|src|src_path|dst|dest|archive|member)\b",
            re.IGNORECASE,
        ),
    ),
]

# ----------------------------------------------------------------------
# Authorization
# ----------------------------------------------------------------------
AUTHORIZATION_PATTERNS: list[tuple[str, Pattern[str]]] = [
    # Evidence of an authorization/ownership check on or near the line.
    (
        "authz-check-present",
        re.compile(
            r"\b(is_owner|owns|has_permission|has_role|require_auth|login_required|"
            r"permission_required|authorize|check_permission|can_access|current_user|"
            r"request\.user|verify_token|enforce|user\.id\s*==|owner_id\s*==)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "authz-tenant-scope",
        re.compile(r"\b(tenant_id|org_id|account_id|team_id|project_id|workspace_id)\b", re.IGNORECASE),
    ),
]

# ----------------------------------------------------------------------
# Reliability / Resilience
# ----------------------------------------------------------------------
RELIABILITY_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (
        "retry-loop",
        re.compile(
            r"for\s+\w+\s+in\s+range\s*\(\s*\d+\s*\)\s*:\s*|while\s+[^:]*\b(retry|attempts|tries)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    (
        "retry-without-backoff",
        re.compile(
            r"(time\.sleep|asyncio\.sleep)\s*\(\s*(0|0\.0)\s*\)"
            r"|for\s+\w+\s+in\s+range\s*\(\s*[2-9]\d*\s*\)\s*:",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    (
        "idempotency-evidence",
        re.compile(
            r"\b(idempoten[ct]y|Idempotency-Key|dedup|dedupe|unique_constraint|"
            r"at_least_once|exactly_once)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "non-idempotent-sink",
        re.compile(r"\b(charge|debit|transfer|pay|send_mail|send_email|publish|enqueue|create_order)\s*\("),
    ),
    (
        "ack-after-failure",
        re.compile(r"\b(ack|acknowledge|commit|nack|reject)\s*\(", re.IGNORECASE),
    ),
]

# ----------------------------------------------------------------------
# Architecture / Design
# ----------------------------------------------------------------------
ARCHITECTURE_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (
        "module-mutable-global",
        re.compile(
            r"^[A-Za-z_]\w*\s*=\s*(dict\s*\(\s*\)|list\s*\(\s*\)|set\s*\(\s*\)|"
            r"\{\s*\}|\[\s*\])\s*$",
            re.MULTILINE,
        ),
    ),
    (
        "bypass-service-layer",
        re.compile(r"^\s*from\s+\S+\.\S*\b(models|entities|schemas)\b\s+import\s+\S*", re.MULTILINE),
    ),
    (
        "business-in-route",
        re.compile(
            r"@\w+\.(get|post|put|delete|patch)\s*\([^)]*\)\s*\n\s*def\s+\w+\s*\([^)]*\)\s*:\s*\n"
            r"\s*(db|session|repository|service)\s*\.\s*(query|add|delete|update|commit)",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
]

# ----------------------------------------------------------------------
# Compatibility
# ----------------------------------------------------------------------
COMPATIBILITY_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (
        "schema-shape-change",
        re.compile(
            r"\b(schema|avro|protobuf|proto|wire_format|serialize|deserialize|migration|"
            r"event_type|message_type|version)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "renamed-config",
        re.compile(
            r"\b(renamed|deprecat|migrat|backward|compatib|old_client|breaking)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "flag-flip",
        re.compile(r"\b(feature_flag|feature_flags|flags?\[|get_flag|is_enabled|rollout)\b", re.IGNORECASE),
    ),
]

# ----------------------------------------------------------------------
# Configuration / Deployment
# ----------------------------------------------------------------------
CONFIGURATION_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (
        "env-var-read",
        re.compile(r"os\.(environ|getenv)\s*\[?[\"']([A-Z][A-Z0-9_]{2,})[\"']", re.IGNORECASE),
    ),
    (
        "config-reference",
        re.compile(r"\b(settings|config|Configuration)\.[A-Za-z_]\w*\b"),
    ),
    (
        "deployment-manifest",
        re.compile(
            r"(ports\s*:|containerPort\s*:|image\s*:|env\s*:|secrets?\s*:|configMap|"
            r"healthCheck|readiness|startupProbe)",
            re.IGNORECASE,
        ),
    ),
    (
        "env-default-mismatch",
        re.compile(r"getenv\s*\(\s*[\"'][A-Z][A-Z0-9_]{2,}[\"']\s*,\s*[\"'][^\"']*[\"']\s*\)"),
    ),
]

# ----------------------------------------------------------------------
# Resource Lifecycle
# ----------------------------------------------------------------------
RESOURCE_LIFECYCLE_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (
        "open-no-with",
        re.compile(
            r"^\s*(?!with\b)(?:[A-Za-z_]\w*\s*=\s*)?\bopen\s*\([^)]*\)(?!\s*as\b)",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    (
        "lock-acquired",
        re.compile(r"(\.acquire\s*\(|threading\.Lock\s*\(|asyncio\.Lock\s*\(|RLock\s*\()", re.IGNORECASE),
    ),
    (
        "timer-registered",
        re.compile(r"\b(setInterval|setTimeout|Timer|schedule\.every|add_periodic_task|loop\.call_later)\s*\("),
    ),
    (
        "listener-subscribed",
        re.compile(r"\b(addEventListener|on\(|subscribe|connect|listen|register_handler|signal\.connect)\s*\("),
    ),
    (
        "temp-file-created",
        re.compile(r"\b(tempfile\.|TemporaryFile|NamedTemporaryFile|mkstemp|mkdtemp)\b"),
    ),
    (
        "transaction-started",
        re.compile(r"\b(begin\s*\(|start_transaction|session\.begin|\.transaction\s*\()", re.IGNORECASE),
    ),
]

# ----------------------------------------------------------------------
# Dependency Chain Analysis
# ----------------------------------------------------------------------
DEPENDENCY_CHAIN_PATTERNS: list[tuple[str, Pattern[str]]] = [
    # Known vulnerable package names in dependency files
    (
        "dep-chain-vulnerable-pkg",
        re.compile(
            r"\b(log4j|lodash|moment|xmlrpc|pyyaml|pillow|urllib3|certifi|cryptography)\b",
            re.IGNORECASE,
        ),
    ),
    # Unpinned transitive dependencies (>= or ~= but no upper bound)
    (
        "dep-chain-unpinned-transitive",
        re.compile(r"[\w.\-]+\s*[>=~]=\s*\d+(?:\.\d+)*[^<>=~]"),
    ),
    # Hash-pinned dependencies (good - chain is pinned)
    (
        "dep-chain-pinned-hash",
        re.compile(r"--hash\s*=\s*(sha256|sha384|sha512):[A-Za-z0-9]+", re.IGNORECASE),
    ),
    # Heavy/cloud-cost-impacting packages
    (
        "dep-chain-heavy-dep",
        re.compile(
            r"\b(tensorflow|torch|pandas|numpy|scipy|transformers|scikit-learn)\b",
            re.IGNORECASE,
        ),
    ),
    # Git-sourced dependencies
    (
        "dep-chain-git-dep",
        re.compile(r"git\s*\+\s*(https|ssh)://", re.IGNORECASE),
    ),
]

# ----------------------------------------------------------------------
# Compliance & Regulation
# ----------------------------------------------------------------------
COMPLIANCE_PATTERNS: list[tuple[str, Pattern[str]]] = [
    # GDPR PII field detection
    (
        "gdpr-pii-field",
        re.compile(
            r"\b(?:email|phone|dob|date_of_birth|ssn|address|full_name|"
            r"first_name|last_name|ip_address|user_agent)\b",
            re.IGNORECASE,
        ),
    ),
    # GDPR consent markers missing
    (
        "gdpr-no-consent",
        re.compile(
            r"\b(?:insert|create|save)\b.*?(?:email|phone|dob|address|user_agent)"
            r"(?!.*?(?:consent|gdpr| lawful|permission))",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # HIPAA PHI field detection
    (
        "hipaa-phi-field",
        re.compile(
            r"\b(?:diagnosis|medication|treatment|patient|health_record|medical|"
            r"dob|mrn|insurance|clinical|lab_result)\b",
            re.IGNORECASE,
        ),
    ),
    # PCI-DSS card data detection
    (
        "pci-dss-card-data",
        re.compile(
            r"\b(?:card_number|cvv|cvc|pan|cardholder|expiry|credit_card|"
            r"payment_card|debit_card|card\s*number)\b",
            re.IGNORECASE,
        ),
    ),
    # PCI-DSS missing encryption
    (
        "pci-dss-no-encrypt",
        re.compile(
            r"(?:card_number|cvv|cvc|pan|credit_card)\s*=\s*[^#]+"
            r"(?!\s*(?:encrypt|hash|mask|vault|tokenize))",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # SOC2 missing audit trail
    (
        "soc2-missing-audit",
        re.compile(
            r"\b(?:create|update|delete|insert|remove)\b.*?"
            r"(?:user|resource|permission|role|access)\b.*?"
            r"(?!.*?(?:audit_log|log_event|record_action|track))",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # SOC2 access control gaps
    (
        "soc2-access-control",
        re.compile(
            r"@(?:app|bp|router)\.(?:post|put|delete|patch|route)\s*\([^)]*\).*?"
            r"(?:admin|admin_only|super_user|permission_required|role_required)?"
            r"(?!.*?(?:current_user|user_id|auth|authorize|permission))",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
]

# ----------------------------------------------------------------------
CATEGORY_PATTERNS_EXTRA: dict[str, list[tuple[str, Pattern[str]]]] = {
    "authorization": AUTHORIZATION_PATTERNS,
    "reliability": RELIABILITY_PATTERNS,
    "architecture": ARCHITECTURE_PATTERNS,
    "compatibility": COMPATIBILITY_PATTERNS,
    "configuration": CONFIGURATION_PATTERNS,
    "resource_lifecycle": RESOURCE_LIFECYCLE_PATTERNS,
    "dependency_chain": DEPENDENCY_CHAIN_PATTERNS,
    "compliance": COMPLIANCE_PATTERNS,
}
