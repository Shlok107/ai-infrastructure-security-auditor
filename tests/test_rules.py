"""Unit tests for Phase 3 — Baseline Rule-Based Security Scanner.

Tests the 10 initial security rules from rules_catalog.py against
positive and negative fixtures. Verifies:
- Rules fire correctly on vulnerable configurations (positive)
- Rules do NOT fire on safe configurations (negative)
- All findings use the src.models.Finding schema
- Deterministic results on identical inputs
- Exit criteria: scanner detects seeded issues, avoids false positives, reproducible
"""

from __future__ import annotations

from typing import Any

import pytest

from src.models import Finding, Resource, Severity
from src.parsers.base import (
    DockerfileParser,
    KubernetesParser,
    TerraformParser,
)
from src.rules.base_rule import Rule, RuleEngine, initialize_rules
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

# Ensure rules are registered
RULES: list[Rule] = initialize_rules()
ENGINE: RuleEngine = RuleEngine(rules=RULES)


# ---- Positive test fixtures (vulnerable configurations) ----

POSITIVE_FIXTURES: dict[str, dict[str, Any]] = {
    "dockerfile_root_user": {
        "description": "Dockerfile with USER root should trigger NO_ROOT_USER",
        "dockerfile": 'FROM python:3.11-slim\nWORKDIR /app\nCOPY . /app\nRUN pip install -r requirements.txt\nUSER root\nCMD ["python", "app.py"]',
        "expected_rule": NO_ROOT_USER,
        "expected_severity": Severity.HIGH,
    },
    "privileged_container": {
        "description": "Dockerfile with Privileged:true should trigger PRIVILEGED_CONTAINER",
        "dockerfile": 'FROM python:3.11-slim\nWORKDIR /app\nCOPY . /app\nRUN pip install -r requirements.txt\nPrivileged: true\nCMD ["python", "app.py"]',
        "expected_rule": PRIVILEGED_CONTAINER,
        "expected_severity": Severity.HIGH,
    },
    "kubernetes_no_security_context": {
        "description": "K8s pod without securityContext should trigger MISSING_SECURITY_CONTEXT",
        "yaml": """apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: test-container
      image: myimage:latest
      resources: {}""",
        "expected_rule": MISSING_SECURITY_CONTEXT,
        "expected_severity": Severity.HIGH,
    },
    "permicious_caps": {
        "description": "Container with permissive capabilities should trigger PERMISSIVE_CAPS",
        "dockerfile": 'FROM python:3.11-slim\nRUN useradd -m appuser\nUSER appuser\nRUN echo \'cap-add ALL\' >> /etc/sudoers\nCMD ["python", "app.py"]',
        "expected_rule": PERMISSIVE_CAPS,
        "expected_severity": Severity.HIGH,
    },
    "embedded_secrets": {
        "description": "Dockerfile with password in ENV should trigger EMBEDDED_SECRETS",
        "dockerfile": 'FROM python:3.11-slim\nENV DB_PASSWORD=EXAMPLE_NOT_A_SECRET\nCMD ["python", "app.py"]',
        "expected_rule": EMBEDDED_SECRETS,
        "expected_severity": Severity.CRITICAL,
    },
    "missing_resource_limits": {
        "description": "Kubernetes container without resource limits should trigger MISSING_RESOURCE_LIMITS",
        "yaml": """apiVersion: v1
kind: Pod
metadata:
  name: unlimited-pod
spec:
  containers:
    - name: app
      image: example/app:1""",
        "expected_rule": MISSING_RESOURCE_LIMITS,
        "expected_severity": Severity.MEDIUM,
    },
    "terraform_sg_unrestricted": {
        "description": "TF SG with 0.0.0.0/0 on port 22 should trigger TERRAFORM_SG_UNRESTRICTED",
        "tf": 'resource "aws_security_group" "ssh" {\n  name        = "allow_ssh"\n  description = "Allow SSH from anywhere"\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
        "expected_rule": TERRAFORM_SG_UNRESTRICTED,
        "expected_severity": Severity.HIGH,
    },
    "unpinned_image": {
        "description": "Dockerfile with :latest image should trigger UNPINNED_IMAGE",
        "dockerfile": 'FROM python:latest\nWORKDIR /app\nCMD ["python", "app.py"]',
        "expected_rule": UNPINNED_IMAGE,
        "expected_severity": Severity.HIGH,
    },
    "sensitive_mounts": {
        "description": "Volume mounting / host path should trigger SENSITIVE_MOUNTS",
        "dockerfile": 'FROM python:3.11-slim\nVOLUME ["/host_sys"]\nCMD ["python", "app.py"]',
        "expected_rule": SENSITIVE_MOUNTS,
        "expected_severity": Severity.HIGH,
    },
    "risky_ports": {
        "description": "Exposed port 22 should trigger RISKY_PORTS",
        "dockerfile": 'FROM python:3.11-slim\nEXPOSE 22\nCMD ["python", "app.py"]',
        "expected_rule": RISKY_PORTS,
        "expected_severity": Severity.MEDIUM,
    },
}


# ---- Negative test fixtures (safe configurations) ----

NEGATIVE_FIXTURES: dict[str, dict[str, Any]] = {
    "dockerfile_nonroot": {
        "description": "Dockerfile with non-root user should NOT trigger NO_ROOT_USER",
        "dockerfile": 'FROM python:3.11-slim\nWORKDIR /app\nCOPY . /app\nRUN pip install -r requirements.txt\nUSER appuser\nCMD ["python", "app.py"]',
        "rule": NO_ROOT_USER,
        "should_flag": False,
    },
    "kubernetes_with_security_context": {
        "description": "K8s pod with full securityContext should NOT trigger MISSING_SECURITY_CONTEXT",
        "yaml": """apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: test-container
      image: myimage:latest
      securityContext:
        runAsNonRoot: true
        readOnlyRootFilesystem: true
        runAsUser: 1000
        capabilities:
          drop:
            - ALL""",
        "rule": MISSING_SECURITY_CONTEXT,
        "should_flag": False,
    },
    "kubernetes_pod_with_caps_drop": {
        "description": "K8s pod with capability drop should NOT trigger PERMISSIVE_CAPS",
        "yaml": """apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: test-container
      image: myimage:latest
      securityContext:
        capabilities:
          drop:
            - ALL""",
        "rule": PERMISSIVE_CAPS,
        "should_flag": False,
    },
    "terraform_sg_restricted": {
        "description": "TF SG with restricted CIDR should NOT trigger TERRAFORM_SG_UNRESTRICTED",
        "tf": 'resource "aws_security_group" "ssh" {\n  name        = "allow_ssh"\n  description = "Allow SSH from restricted subnet"\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["10.0.0.0/16"]\n  }\n}\n',
        "rule": TERRAFORM_SG_UNRESTRICTED,
        "should_flag": False,
    },
    "image_pinned": {
        "description": "Dockerfile with pinned image tag should NOT trigger UNPINNED_IMAGE",
        "dockerfile": 'FROM python:3.11.6-slim\nWORKDIR /app\nCMD ["python", "app.py"]',
        "rule": UNPINNED_IMAGE,
        "should_flag": False,
    },
    "with_resource_limits": {
        "description": "Kubernetes container with resource limits should NOT trigger MISSING_RESOURCE_LIMITS",
        "yaml": """apiVersion: v1
kind: Pod
metadata:
  name: limited-pod
spec:
  containers:
    - name: app
      image: example/app:1
      resources:
        limits:
          cpu: 500m
          memory: 256Mi""",
        "rule": MISSING_RESOURCE_LIMITS,
        "should_flag": False,
    },
}


# ---- Positive Tests ----


class TestPositiveFixtures:
    """Test that rules correctly identify vulnerable configurations."""

    @pytest.mark.parametrize("fixture_name, fixture_data", POSITIVE_FIXTURES.items())
    def test_positive(self, fixture_name: str, fixture_data: dict[str, Any]) -> None:
        """All positive fixtures should trigger their expected rule."""
        # Parse the configuration and extract resources
        if "dockerfile" in fixture_data:
            result: Any = DockerfileParser().parse_string(fixture_data["dockerfile"])
            resources = result.resources
        elif "yaml" in fixture_data:
            result: Any = KubernetesParser().parse(fixture_data["yaml"])
            resources = result.resources
        elif "tf" in fixture_data:
            result: Any = TerraformParser().parse(fixture_data["tf"])
            resources = result.resources
        else:
            # Fallback: create Resource manually
            resources = [
                Resource(
                    resource_id="test",
                    resource_type="container",
                    name="test",
                    filename="Dockerfile",
                    line_number=1,
                )
            ]

        # Scan resources with the engine
        findings: list[Finding] = ENGINE.scan(resources)

        # Find the expected rule's finding
        expected_rule = fixture_data["expected_rule"]
        expected_severity = fixture_data["expected_severity"]

        matching_findings = [f for f in findings if f.rule_id == expected_rule.rule_id]

        assert len(matching_findings) > 0, (
            f"Positive test {fixture_name}: expected rule {expected_rule.rule_id} "
            f"to fire, but no matching findings found. "
            f"All findings: {[f.rule_id for f in findings]}"
        )

        finding = matching_findings[0]
        assert finding.severity == expected_severity, (
            f"Positive test {fixture_name}: expected severity {expected_severity}, "
            f"got {finding.severity}"
        )
        assert finding.rule_id == expected_rule.rule_id
        assert finding.resource is not None
        assert len(finding.evidence) > 0
        assert len(finding.remediation) > 0
        assert len(finding.references) > 0

    def test_all_rules_deterministic(self) -> None:
        """Running the scanner twice on the same input should produce identical results."""
        # Use the dockerfile_root_user positive fixture
        dockerfile = POSITIVE_FIXTURES["dockerfile_root_user"]["dockerfile"]
        result1: Any = DockerfileParser().parse(dockerfile)
        findings1: list[Finding] = ENGINE.scan(result1.resources)

        result2: Any = DockerfileParser().parse(dockerfile)
        findings2: list[Finding] = ENGINE.scan(result2.resources)

        assert len(findings1) == len(
            findings2
        ), f"Determinism check failed: {len(findings1)} vs {len(findings2)} findings"

        for f1, f2 in zip(
            sorted(findings1, key=lambda f: f.rule_id),
            sorted(findings2, key=lambda f: f.rule_id),
        ):
            assert f1.rule_id == f2.rule_id
            assert f1.severity == f2.severity
            assert f1.resource.resource_id == f2.resource.resource_id
            assert f1.title == f2.title


# ---- Negative Tests ----


class TestNegativeFixtures:
    """Test that rules correctly disregard safe configurations."""

    @pytest.mark.parametrize("fixture_name, fixture_data", NEGATIVE_FIXTURES.items())
    def test_negative(self, fixture_name: str, fixture_data: dict[str, Any]) -> None:
        """All negative fixtures should NOT trigger their rule."""
        # Parse the configuration
        if "dockerfile" in fixture_data:
            result: Any = DockerfileParser().parse(fixture_data["dockerfile"])
            resources = result.resources
        elif "yaml" in fixture_data:
            result: Any = KubernetesParser().parse(fixture_data["yaml"])
            resources = result.resources
        elif "tf" in fixture_data:
            result: Any = TerraformParser().parse(fixture_data["tf"])
            resources = result.resources
        else:
            resources = [
                Resource(
                    resource_id="test",
                    resource_type="container",
                    name="test",
                    filename="Dockerfile",
                    line_number=1,
                )
            ]

        # Scan resources with the engine
        findings: list[Finding] = ENGINE.scan(resources)

        # Check that the rule is NOT present in findings
        rule = fixture_data["rule"]
        matching_findings = [f for f in findings if f.rule_id == rule.rule_id]

        assert len(matching_findings) == 0, (
            f"Negative test {fixture_name}: rule {rule.rule_id} should NOT fire, "
            f"but found {len(matching_findings)} matching findings: "
            f"[{', '.join(f.rule_id for f in matching_findings)}]"
        )


# ---- Engine Integration Tests ----


class TestEngineIntegration:
    """Test the RuleEngine integration with parsed configurations."""

    def test_scan_returns_finding_schema(self) -> None:
        """All findings should conform to src.models.Finding schema."""
        # Parse a simple Dockerfile
        dockerfile = (
            'FROM python:3.11-slim\nUSER root\nWORKDIR /app\nCMD ["python", "app.py"]'
        )
        result: Any = DockerfileParser().parse(dockerfile)
        findings: list[Finding] = ENGINE.scan(result.resources)

        assert len(findings) > 0
        for f in findings:
            # Verify Finding has all required fields
            assert hasattr(f, "rule_id")
            assert hasattr(f, "title")
            assert hasattr(f, "severity")
            assert hasattr(f, "confidence")
            assert hasattr(f, "resource")
            assert hasattr(f, "evidence")
            assert hasattr(f, "remediation")
            assert hasattr(f, "references")

            # Verify types
            assert isinstance(f.rule_id, str)
            assert isinstance(f.title, str)
            assert isinstance(f.severity, Severity)
            assert isinstance(f.confidence, float)
            assert isinstance(f.resource, Resource)
            assert isinstance(f.evidence, str)
            assert isinstance(f.remediation, str)
            assert isinstance(f.references, list)

    def test_scan_sorts_by_severity(self) -> None:
        """Findings should be sorted by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)."""
        # Use a config that triggers multiple rule severities
        dockerfile = """FROM python:3.11-slim
USER root
EXPOSE 22
VOLUME ["/host_sys"]
Privileged: true
CMD ["python", "app.py"]"""
        result: Any = DockerfileParser().parse(dockerfile)
        findings: list[Finding] = ENGINE.scan(result.resources)

        if len(findings) >= 2:
            # Verify severity ordering
            severity_order = {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "INFO": 4,
            }
            for i in range(len(findings) - 1):
                s1 = severity_order.get(str(findings[i].severity), 99)
                s2 = severity_order.get(str(findings[i + 1].severity), 99)
                assert s1 <= s2, (
                    f"Findings not sorted by severity: {findings[i].severity} ({s1}) "
                    f"before {findings[i + 1].severity} ({s2})"
                )

    def test_deduplication(self) -> None:
        """Duplicate findings (same rule_id + resource_id + severity) should be removed."""
        # Scan the same resource multiple times conceptually
        # by running engine on same resources
        dockerfile = 'FROM python:3.11-slim\nUSER root\nCMD ["python", "app.py"]'
        result: Any = DockerfileParser().parse(dockerfile)
        findings: list[Finding] = ENGINE.scan(result.resources)

        # Count by (rule_id, resource_id, severity)
        from collections import Counter

        keys: list[tuple[str, str, str]] = []
        for f in findings:
            keys.append((f.rule_id, f.resource.resource_id, str(f.severity)))
        counts: Counter[tuple[str, str, str]] = Counter(keys)

        # Each unique key should appear exactly once in the output
        for key, count in counts.items():
            matching = [
                f
                for f in findings
                if (f.rule_id, f.resource.resource_id, str(f.severity)) == key
            ]
            assert (
                len(matching) == 1
            ), f"Deduplication failed: key {key} appears {count} times but should be 1"
