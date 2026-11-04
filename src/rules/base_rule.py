"""Rule base class and dataclass for the AI Infrastructure Configuration Auditor.

Defines the versioned rule format as specified in plan.md Phase 3:
"Define a versioned rule format with:
- Rule ID and title
- Description and rationale
- Severity and confidence
- Applicable resource types
- Detection logic
- Evidence requirements
- Remediation guidance
- References to relevant security guidance where available"
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.models import Finding, Resource, Severity


class RuleVersion(str, Enum):
    """Version of the rule format."""

    V1 = "1.0.0"
    V2 = "2.0.0"


@dataclass
class Rule:
    """Versioned base class for a security detection rule.

    Attributes:
        rule_id: Unique rule identifier (e.g. "NO_ROOT_USER", "PRIVILEGED_CONTAINER").
        title: Human-readable rule title/description.
        severity: Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO).
        confidence: Confidence in the finding (0.0-1.0). Default 1.0 (deterministic).
        resource_types: Resource types this rule applies to. Empty list = applies to all.
        detection_logic: Callable that takes a Resource and returns bool (True = rule matches).
        evidence_requirements: Description of what evidence the rule requires.
        remediation_guidance: Recommended remediation steps.
        references: List of links to relevant security guidance (CIS, NIST, etc.).
        version: Rule format version (defaults to V1).
    """

    rule_id: str
    title: str
    severity: Severity
    confidence: float = field(default=1.0)
    resource_types: list[str] = field(default_factory=list)
    detection_logic: Callable[[Any], bool] | None = field(
        default=None
    )  # Callable[[Resource], bool]
    evidence_requirements: str = ""
    remediation_guidance: str = ""
    references: list[str] = field(default_factory=list)
    version: RuleVersion = field(default=RuleVersion.V1)

    def check(self, resource: Resource) -> Finding | None:
        """Check a resource against this rule.

        Args:
            resource: The resource to check.

        Returns:
            A Finding if the rule matches, or None if it does not match.
        """
        # Filter by resource type if resource_types is specified
        if self.resource_types and not any(
            rt in resource.resource_type for rt in self.resource_types
        ):
            return None

        # Run detection logic
        if self.detection_logic is not None:
            matches = self.detection_logic(resource)
        else:
            matches = False

        if matches:
            return Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                confidence=self.confidence,
                resource=resource,
                evidence=self.evidence_requirements,
                description="",
                remediation=self.remediation_guidance,
                references=self.references,
            )
        else:
            return None


class RuleEngine:
    """Engine for running all registered rules against a set of resources.

    Responsibilities:
    - Iterate registered rules
    - Apply each rule to each resource
    - Aggregate findings into a stable machine-readable schema
    - Provide methods for filtering, sorting, and deduplicating findings
    """

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else initialize_rules()

    def scan(self, resources: list[Resource]) -> list[Finding]:
        """Run all rules against all resources and return aggregated findings.

        Args:
            resources: List of Resource objects to scan.

        Returns:
            List of Finding objects, sorted by (severity DESC, rule_id ASC).
        """
        findings: list[Finding] = []

        for resource in resources:
            for rule in self.rules:
                finding = rule.check(resource)
                if finding is not None:
                    findings.append(finding)

        # Deduplicate: same rule_id + same resource_id + same severity
        seen: set[tuple[str, str, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.resource.resource_id, str(f.severity))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO) then rule_id
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        unique.sort(key=lambda f: (severity_order.get(f.severity, 99), f.rule_id))

        return unique

    def scan_resource(self, resource: Resource) -> list[Finding]:
        """Run all rules against a single resource.

        Convenience method for scanning one resource.
        """
        return self.scan([resource])


def initialize_rules() -> list[Rule]:
    """Initialize and return the full list of registered rules.

    This is called once at module import time to populate the Rule registry.
    The rules defined in rules_catalog.py are imported and registered here.
    """
    from src.rules.rules_catalog import (
        EMBEDDED_SECRETS,
        MISSING_RESOURCE_LIMITS,
        MISSING_SECURITY_CONTEXT,
        NO_ROOT_USER,
        PERMISSIVE_CAPS,
        PRIVILEGED_CONTAINER,
        RISKY_PORTS,
        SENSITIVE_MOUNTS,
        TERRAFORM_SG_UNRESTRICTED,
        UNPINNED_IMAGE,
    )

    return [
        NO_ROOT_USER,
        PRIVILEGED_CONTAINER,
        SENSITIVE_MOUNTS,
        RISKY_PORTS,
        MISSING_SECURITY_CONTEXT,
        PERMISSIVE_CAPS,
        EMBEDDED_SECRETS,
        MISSING_RESOURCE_LIMITS,
        TERRAFORM_SG_UNRESTRICTED,
        UNPINNED_IMAGE,
    ]


# End of base_rule.py
