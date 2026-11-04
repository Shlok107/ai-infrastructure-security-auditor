"""Core data models for the AI Infrastructure Configuration Auditor.

Defined per plan.md Phase 1 task:
"Define common data models for resources, relationships, rules, findings,
evidence, severity, and remediation actions."
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings as string values.

    Using str, Enum so Pydantic v2 can serialize/deserialize natively.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Resource(BaseModel):
    """Base model representing an infrastructure resource.

    Attributes:
        resource_id: Unique identifier for the resource.
        resource_type: Type of resource (e.g. 'container', 'service', 'volume').
        name: Human-readable resource name.
        filename: Source file where this resource was defined.
        line_number: Line number in source file, if available.
        evidence: Relevant snippet/text from the source file related to this resource.
    """

    resource_id: str = Field(..., description="Unique identifier for the resource")
    resource_type: str = Field(..., description="Type of infrastructure resource")
    name: str = Field(..., description="Human-readable resource name")
    filename: str = Field(..., description="Source file where resource was defined")
    line_number: int | None = Field(
        None, description="Line number in source file, if available"
    )
    evidence: str = Field(
        "",
        description="Relevant snippet/text from source file related to this resource",
    )

    model_config = {"frozen": True, "use_enum_values": True}


class Evidence(BaseModel):
    """Evidence supporting a finding, with source reference.

    Attributes:
        source_file: File where evidence was found.
        source_line: Line number in source file, if available.
        snippet: Relevant code/snippet fragment.
        position: Line/column position information.
    """

    source_file: str = Field(..., description="File where evidence was found")
    source_line: int | None = Field(
        None, description="Line number in source file, if available"
    )
    snippet: str = Field("", description="Relevant code/snippet fragment")
    position: dict[str, int] = Field(
        default_factory=dict, description="Line/column position information"
    )

    model_config = {"frozen": True}


class Finding(BaseModel):
    """A security finding / rule result.

    Attributes:
        rule_id: Unique rule identifier.
        title: Human-readable finding title.
        severity: Severity level.
        confidence: Confidence in this finding (0.0-1.0).
        resource: Affected infrastructure resource.
        evidence: Evidence supporting this finding.
        description: Detailed description of the issue.
        remediation: Recommended remediation steps.
        references: Links to relevant security guidance.
    """

    rule_id: str = Field(..., description="Unique rule identifier")
    title: str = Field(..., description="Human-readable finding title")
    severity: Severity = Field(..., description="Severity level")
    confidence: float = Field(
        1.0, ge=0.0, le=1.0, description="Confidence in this finding (0.0-1.0)"
    )
    resource: Resource = Field(..., description="Affected infrastructure resource")
    evidence: str = Field(..., description="Evidence supporting this finding")
    description: str = Field("", description="Detailed description of the issue")
    remediation: str = Field("", description="Recommended remediation steps")
    references: list[str] = Field(
        default_factory=list, description="Links to relevant security guidance"
    )

    model_config = {"frozen": True}

    def is_high_severity(self) -> bool:
        """Return True if severity is CRITICAL or HIGH."""
        return self.severity in (Severity.CRITICAL, Severity.HIGH)


class Rule(BaseModel):
    """Base class for a security detection rule.

    Attributes:
        rule_id: Unique rule identifier.
        title: Rule title/description.
        severity: Default severity for this rule.
        resource_types: Resource types this rule applies to.
        is_active: Whether the rule is active.
    """

    rule_id: str = Field(..., description="Unique rule identifier")
    title: str = Field(..., description="Rule title/description")
    severity: Severity = Field(..., description="Default severity for this rule")
    resource_types: list[str] = Field(
        default_factory=list, description="Resource types this rule applies to"
    )
    is_active: bool = Field(True, description="Whether the rule is active")

    model_config = {"frozen": True}

    def check(self, resource: Resource) -> Finding | None:
        """Check a resource against this rule.

        Subclasses must implement this method; return a Finding or None.
        """
        raise NotImplementedError("Subclasses must implement .check()")


class RemediationAction(BaseModel):
    """A remediation action with affected resources and expected impact.

    Attributes:
        action_id: Unique action identifier.
        description: Description of the fix.
        affected_resources: Resource IDs affected by this action.
        risk_reduction: Descriptive risk reduction (e.g. 'reduces attack surface').
        operational_impact: Expected operational impact (e.g. 'none', 'restart required').
    """

    action_id: str = Field(..., description="Unique action identifier")
    description: str = Field(..., description="Description of the fix")
    affected_resources: list[str] = Field(
        default_factory=list, description="Resource IDs affected by this action"
    )
    risk_reduction: str = Field("", description="Descriptive risk reduction")
    operational_impact: str = Field("", description="Expected operational impact")

    model_config = {"frozen": True}


class Relationship(BaseModel):
    """Typed edge between two nodes in the knowledge graph (Phase 4+).

    Attributes:
        source_id: Source resource ID.
        target_id: Target resource ID.
        relationship_type: Type of relationship (e.g. 'exposes', 'mounts', 'uses_image').
        evidence: Evidence supporting this relationship.
        confidence: Confidence in this relationship (0.0-1.0).
    """

    source_id: str = Field(..., description="Source resource ID")
    target_id: str = Field(..., description="Target resource ID")
    relationship_type: str = Field(..., description="Type of relationship")
    evidence: str = Field("", description="Evidence supporting this relationship")
    confidence: float = Field(
        1.0, ge=0.0, le=1.0, description="Confidence in this relationship"
    )

    model_config = {"frozen": True}
