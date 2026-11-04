"""Initial security rule pack for Phase 3 — Baseline Rule-Based Security Scanner.

Defines 10 high-value security checks as specified in plan.md Phase 3:
- Containers configured to run as root or without an explicit non-root user
- Privileged containers
- Sensitive host-path mounts or excessive host access
- Broad or risky port exposure
- Kubernetes workloads missing relevant security-context restrictions
- Containers configured with overly permissive capabilities
- Secrets embedded directly in configuration
- Missing or risky resource limits where applicable
- Terraform security-group rules allowing unrestricted ingress on sensitive ports
- Unpinned or mutable container image references

Each rule follows the Rule dataclass format from base_rule.py and produces
findings via the src.models.Finding schema (machine-readable).
"""

from __future__ import annotations

from src.models import Resource, Severity
from src.rules.base_rule import Rule, RuleVersion

# ---- Severity helper ----


def _high_severity() -> Severity:
    return Severity.HIGH


def _critical_severity() -> Severity:
    return Severity.CRITICAL


def _medium_severity() -> Severity:
    return Severity.MEDIUM


# ---- Detection logic helpers ----


def _resource_type_matches(resource: Resource, types: list[str]) -> bool:
    """Check if resource.resource_type matches any of the given types."""
    if not types:
        return True
    return any(t in resource.resource_type for t in types)


def _evidence(resource: Resource, snippet: str) -> str:
    """Build evidence string from resource and snippet."""
    return f"{resource.filename}:{resource.line_number} - {snippet}"


# ---- Rule: NO_ROOT_USER ----


def _detect_root_user(resource: Resource) -> bool:
    """Detection logic: resource is a 'user' type named 'root'."""
    return _resource_type_matches(
        resource, ["user", "nonroot_user"]
    ) and resource.name.lower() in ("root", "0")


NO_ROOT_USER = Rule(
    rule_id="NO_ROOT_USER",
    title="Dockerfile runs as root user",
    severity=Severity.HIGH,
    confidence=1.0,
    resource_types=["user"],
    detection_logic=_detect_root_user,
    evidence_requirements="USER root directive in Dockerfile implies running as root",
    remediation_guidance="Use a non-root user with USER <username> after FROM",
    references=[
        "https://cis-benchmarks.org/",
        "NIST 800-190 Container Security Guide",
    ],
    version=RuleVersion.V1,
)

# ---- Rule: PRIVILEGED_CONTAINER ----


def _detect_privileged_container(resource: Resource) -> bool:
    """Detection logic: resource indicates privileged container mode.

    Checks for 'privileged' in the resource name or evidence.
    The Rule's resource_types handles type filtering (set to [] for all types).
    """
    name_lower = resource.name.lower() if resource.name else ""
    evidence_lower = resource.evidence.lower() if resource.evidence else ""
    is_privileged = "privileged" in name_lower or "privileged" in evidence_lower
    return is_privileged


PRIVILEGED_CONTAINER = Rule(
    rule_id="PRIVILEGED_CONTAINER",
    title="Container runs in privileged mode",
    severity=Severity.HIGH,
    confidence=1.0,
    resource_types=[],
    detection_logic=_detect_privileged_container,
    evidence_requirements="Privileged: true directive in Dockerfile",
    remediation_guidance="Remove Privileged directive; use least-capability approach; run as non-root user",
    references=[
        "https://kubernetes.io/docs/security/",
        "CIS Kubernetes Benchmark",
    ],
    version=RuleVersion.V1,
)

# ---- Rule: SENSITIVE_MOUNTS ----


def _detect_sensitive_mounts(resource: Resource) -> bool:
    """Detection logic: volume resource points to sensitive host paths."""
    sensitive_paths = ["/", "/etc", "/boot", "/var", "/home", "/root"]
    name_lower = resource.name.lower()
    return any(name_lower.startswith(p) or p in name_lower for p in sensitive_paths)


SENSITIVE_MOUNTS = Rule(
    rule_id="SENSITIVE_MOUNTS",
    title="Sensitive host-path mount or excessive host access",
    severity=Severity.HIGH,
    confidence=1.0,
    resource_types=["volume"],
    detection_logic=_detect_sensitive_mounts,
    evidence_requirements="Host-path volume mounting sensitive system directories",
    remediation_guidance="Use named volumes or emptyDir; avoid host-path to /, /etc, /var; run with least privilege",
    references=[
        "https://kubernetes.io/docs/concepts/storage/volumes/",
        "CIS Docker Benchmark",
    ],
    version=RuleVersion.V1,
)

# ---- Rule: RISKY_PORTS ----


def _detect_risks_ports(resource: Resource) -> bool:
    """Detection logic: exposed port is below 1020 or is a well-known service port."""
    port_name = resource.name.lower()
    # Ports below 1020 are privileged ports
    # Check if it looks like a port number
    try:
        port_val = int(
            port_name.split("/")[0].split(":")[-1]
        )  # handle "8080:80" format
        is_privileged_port = 1 <= port_val <= 1020
    except ValueError:
        # Not a numeric port; check well-known names
        is_privileged_port = port_name in (
            "22",
            "23",
            "53",
            "69",
            "110",
            "123",
            "143",
            "993",
            "995",
        )
        return is_privileged_port
    return is_privileged_port


RISKY_PORTS = Rule(
    rule_id="RISKY_PORTS",
    title="Broad or risky port exposure",
    severity=Severity.MEDIUM,
    confidence=0.8,
    resource_types=["exposed_port"],
    detection_logic=_detect_risks_ports,
    evidence_requirements="Port exposure without restriction or on privileged port range",
    remediation_guidance="Restrict port exposure; use allow-lists; map only required ports; consider non-privileged ports (>1020)",
    references=[
        "https://cisecurity.org/benchmark/docker/",
        "NIST SP 800-53",
    ],
    version=RuleVersion.V1,
)

# ---- Rule: MISSING_SECURITY_CONTEXT ----


def _detect_missing_security_context(resource: Resource) -> bool:
    """Detection logic: K8s resource has no security context restrictions.

    Checks that the resource does NOT have evidence of:
    - readOnlyRootFilesystem
    - runAsNonRoot
    - runAsUser (non-root)
    """
    evidence_lower = resource.evidence.lower() if resource.evidence else ""
    if not resource.filename.lower().endswith((".yaml", ".yml")):
        return False
    has_roc = (
        "readonlyrootfilesystem" in evidence_lower
        or "read-only-root-filesystem" in evidence_lower
    )
    has_nonroot = (
        "runasnonroot" in evidence_lower or "run-as-non-root" in evidence_lower
    )
    has_runasuser = "runasuser" in evidence_lower
    # Rule fires when security context is missing (none of the above present)
    has_any_security = has_roc or has_nonroot or has_runasuser
    return not has_any_security and _resource_type_matches(
        resource, ["pod", "deployment", "container"]
    )


MISSING_SECURITY_CONTEXT = Rule(
    rule_id="MISSING_SECURITY_CONTEXT",
    title="Kubernetes workloads missing security-context restrictions",
    severity=Severity.HIGH,
    confidence=0.9,
    resource_types=["pod", "deployment", "container"],
    detection_logic=_detect_missing_security_context,
    evidence_requirements="No readOnlyRootFilesystem, runAsNonRoot, or runAsUser set in pod spec",
    remediation_guidance="Add securityContext with readOnlyRootFilesystem=True, runAsNonRoot=True, and runAsUser set to non-root user",
    references=[
        "https://kubernetes.io/docs/concepts/security/security-context/",
        "CIS Kubernetes Benchmark",
    ],
    version=RuleVersion.V1,
)

# ---- Rule: PERMISSIVE_CAPS ----


def _detect_permissive_caps(resource: Resource) -> bool:
    """Detection logic: container has overly permissive capabilities.

    Checks for CAP_ADD ALL or other broadly-granted capabilities.
    """
    caps_lower = resource.name.lower() if resource.name else ""
    evidence_lower = resource.evidence.lower() if resource.evidence else ""
    # Check for "ALL" capability addition
    has_all_caps = (
        "cap_addALL" in caps_lower or "all" in evidence_lower.split()
        if evidence_lower
        else False
    )
    # Check for NET_RAW or other highly permissive caps
    has_net_raw = "net_raw" in caps_lower or "net_raw" in evidence_lower
    # Check for generic permissive wording
    permissive_keywords = ["all", "any", "unconfined", "sys_admin"]
    has_permissive_kw = any(
        kw in caps_lower or kw in evidence_lower for kw in permissive_keywords
    )
    return has_all_caps or has_net_raw or has_permissive_kw


PERMISSIVE_CAPS = Rule(
    rule_id="PERMISSIVE_CAPS",
    title="Container with overly permissive capabilities",
    severity=Severity.HIGH,
    confidence=0.85,
    resource_types=[],
    detection_logic=_detect_permissive_caps,
    evidence_requirements="CAP_ADD ALL, NET_RAW, or other broadly-granted capabilities",
    remediation_guidance="Grant only minimum required capabilities; avoid CAP_ADD ALL; use Linux capabilities sparingly",
    references=[
        "https://kubernetes.io/docs/concepts/security/linux-capabilities/",
        "CIS Docker Benchmark",
    ],
    version=RuleVersion.V1,
)

# ---- Rule: EMBEDDED_SECRETS ----


def _detect_embedded_secrets(resource: Resource) -> bool:
    """Detection logic: secrets embedded in configuration.

    Checks for common secret patterns in environment variable names
    and evidence: PASSWORD, SECRET, TOKEN, KEY patterns.
    """
    name_lower = resource.name.lower() if resource.name else ""
    evidence_lower = resource.evidence.lower() if resource.evidence else ""
    secret_patterns = [
        "password",
        "secret",
        "token",
        "api_key",
        "key",
        "credentials",
    ]
    # Check name and evidence for secret-related patterns
    name_has_secret = any(p in name_lower for p in secret_patterns)
    evidence_has_secret = any(p in evidence_lower for p in secret_patterns)
    # Also check for common secret values patterns (simplified)
    # Look for values that look like passwords/tokens (base64-ish, or common prefixes)
    secret_value_patterns = ["sk-", "pk-", "auth-", "pwd-", "secret="]
    evidence_has_secret_value = any(p in evidence_lower for p in secret_value_patterns)
    return name_has_secret or evidence_has_secret or evidence_has_secret_value


EMBEDDED_SECRETS = Rule(
    rule_id="EMBEDDED_SECRETS",
    title="Secrets embedded directly in configuration",
    severity=Severity.CRITICAL,
    confidence=0.95,
    resource_types=["environment_variable"],
    detection_logic=_detect_embedded_secrets,
    evidence_requirements="Password, secret, token, or key found in ENV var or config file without secret management",
    remediation_guidance="Use secret management solutions (e.g., Kubernetes Secrets, HashiCorp Vault, AWS Secrets Manager); never hard-code secrets in configuration",
    references=[
        "https://kubernetes.io/docs/concepts/configmap/#secret",
        "NIST 800-57",
    ],
    version=RuleVersion.V1,
)

# ---- Rule: MISSING_RESOURCE_LIMITS ----


def _detect_missing_resource_limits(resource: Resource) -> bool:
    """Detection logic: container resource has no memory or CPU limits.

    Checks that resource limits are not set, or are set to unlimited/"*".
    """
    # This is a simplified check; in a full implementation, would inspect
    # the full resource spec. For now, check that the resource name/evidence
    # does NOT contain limit indicators.
    name_lower = resource.name.lower() if resource.name else ""
    evidence_lower = resource.evidence.lower() if resource.evidence else ""
    if not resource.filename.lower().endswith((".yaml", ".yml")):
        return False
    if "resource limits missing" in evidence_lower:
        return True
    has_limits = (
        "limits" in name_lower
        or "limits" in evidence_lower
        or "memory" in name_lower
        or "cpu" in name_lower
    )
    # Rule fires when no limits are detected at all
    return not has_limits and _resource_type_matches(resource, ["container"])


MISSING_RESOURCE_LIMITS = Rule(
    rule_id="MISSING_RESOURCE_LIMITS",
    title="Missing or risky resource limits",
    severity=Severity.MEDIUM,
    confidence=0.7,
    resource_types=["container"],
    detection_logic=_detect_missing_resource_limits,
    evidence_requirements="No memory or CPU resource limits defined in container spec",
    remediation_guidance="Set memory and CPU limits; avoid setting limits to '*' or 'unlimited'; use resource requests too",
    references=[
        "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
        "CIS Kubernetes Benchmark",
    ],
    version=RuleVersion.V1,
)

# ---- Rule: TERRAFORM_SG_UNRESTRICTED ----


def _detect_terraform_sg_unrestricted(resource: Resource) -> bool:
    """Detection logic: Terraform security group allows unrestricted ingress on sensitive ports.

    Checks for cidr_blocks containing 0.0.0.0/0 on ports 22 (SSH) or 3389 (RDP).
    """
    name_lower = resource.name.lower() if resource.name else ""
    evidence_lower = resource.evidence.lower() if resource.evidence else ""
    # Check for unrestricted ingress patterns
    has_unrestricted_cidr = "0.0.0.0/0" in evidence_lower or "0.0.0.0/0" in name_lower
    is_sensitive_port = (
        "22" in evidence_lower
        or "22" in name_lower
        or "3389" in evidence_lower
        or "3389" in name_lower
    )
    return has_unrestricted_cidr and is_sensitive_port


TERRAFORM_SG_UNRESTRICTED = Rule(
    rule_id="TERRAFORM_SG_UNRESTRICTED",
    title="Terraform security-group rules allowing unrestricted ingress on sensitive ports",
    severity=Severity.HIGH,
    confidence=0.9,
    resource_types=["terraform_aws_security_group"],
    detection_logic=_detect_terraform_sg_unrestricted,
    evidence_requirements="Security group allows ingress from 0.0.0.0/0 on sensitive ports (22/3389)",
    remediation_guidance="Restrict security group rules to required source IPs/cidr blocks; remove unrestricted rules; use allow-lists",
    references=[
        "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
        "Nist 800-53",
    ],
    version=RuleVersion.V1,
)

# ---- Rule: UNPINNED_IMAGE ----


def _detect_unpinned_image(resource: Resource) -> bool:
    """Flag floating ``latest`` and references without a tag or digest."""
    image = (resource.name or "").lower()
    if "@sha256:" in image:
        return False
    # A colon in a registry hostname (registry:port/image) is not a tag.
    last_component = image.rsplit("/", 1)[-1]
    if ":" not in last_component:
        return True
    return last_component.rsplit(":", 1)[-1] == "latest"


UNPINNED_IMAGE = Rule(
    rule_id="UNPINNED_IMAGE",
    title="Unpinned or mutable container image references",
    severity=Severity.HIGH,
    confidence=0.8,
    resource_types=["image"],
    detection_logic=_detect_unpinned_image,
    evidence_requirements="Image uses the floating 'latest' tag or has no tag; digest-pinned references are not flagged",
    remediation_guidance="Replace floating or untagged references with a stable version tag or, preferably, an immutable image digest",
    references=[
        "https://docs.docker.com/engine/reference/commandline/tag/",
        "CIS Docker Benchmark",
    ],
    version=RuleVersion.V1,
)


# ---- Registry initializer ----


def initialize_rules() -> list[Rule]:
    """Initialize and return the full list of registered rules.

    This is called once at module import time to populate the Rule registry.
    """
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
