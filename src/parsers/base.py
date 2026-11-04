"""Parsers that normalize infrastructure configuration into resources.

The parsers are deliberately read-only: they never execute Docker, Terraform,
or Kubernetes configuration. YAML parsing uses PyYAML's safe loader.
"""

from __future__ import annotations

import abc
import os
import re
from typing import Any, ClassVar

import yaml

from src.models import Evidence, Finding, Resource, Severity


class ParseResult:
    """Normalized resources and any errors encountered while parsing."""

    def __init__(self, resources: list[Resource], errors: list[Finding] | None = None):
        self.resources = resources
        self.errors = errors or []

    def add_error(self, finding: Finding) -> None:
        self.errors.append(finding)

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    @property
    def success(self) -> bool:
        return not self.has_errors


class ParseStatus:
    """String statuses retained for callers that need a simple outcome."""

    OK = "ok"
    VALIDATION_ERROR = "validation_error"
    UNSUPPORTED_FORMAT = "unsupported_format"
    PARSE_ERROR = "parse_error"


class BaseParser(abc.ABC):
    """Shared parser interface and resource/error factories."""

    name = "base"
    file_extensions: tuple[str, ...] = ()

    @abc.abstractmethod
    def can_parse(self, file_path: str) -> bool:
        """Return whether the path has an extension handled by this parser."""

    @abc.abstractmethod
    def parse(
        self, file_path: str | None = None, content: str | None = None
    ) -> ParseResult:
        """Parse a path or in-memory configuration string."""

    def validate(self, resource: Resource) -> list[Finding]:
        return []

    def supports_file(self, file_path: str) -> bool:
        base = os.path.basename(file_path).lower()
        return any(base.endswith(ext.lower()) for ext in self.file_extensions)

    def extract_evidence(
        self, file_path: str, line_number: int, snippet: str = ""
    ) -> Evidence:
        return Evidence(source_file=file_path, source_line=line_number, snippet=snippet)

    def error(
        self,
        file_path: str,
        line_number: int,
        message: str,
        severity: Severity = Severity.MEDIUM,
    ) -> Finding:
        return Finding(
            rule_id="PARSER_ERROR",
            title=f"Parse error in {self.name}: {message}",
            severity=severity,
            resource=Resource(
                resource_id=f"{self.name}:{file_path}",
                resource_type=self.name,
                name=file_path,
                filename=file_path,
                line_number=None,
                evidence="",
            ),
            evidence=f"{file_path}:{line_number} - {message}",
            description=message,
            confidence=1.0,
            remediation="",
        )

    def normalize_resource(
        self,
        resource_type: str,
        name: str,
        filename: str,
        line_number: int | None = None,
        **kwargs: Any,
    ) -> Resource:
        return Resource(
            resource_id=f"{resource_type}:{name}",
            resource_type=resource_type,
            name=name,
            filename=filename,
            line_number=line_number,
            **kwargs,
        )

    @staticmethod
    def get_file_content(file_path: str) -> str | None:
        try:
            with open(file_path, encoding="utf-8", errors="replace") as stream:
                return stream.read()
        except OSError:
            return None

    def _content(
        self, file_path: str | None, content: str | None
    ) -> tuple[str, str] | ParseResult:
        if content is not None:
            return content, file_path or self.default_filename
        if file_path is None:
            return ParseResult(
                [],
                [
                    self.error(
                        self.default_filename, 0, "No file path or content provided"
                    )
                ],
            )
        text = self.get_file_content(file_path)
        if text is None:
            return ParseResult([], [self.error(file_path, 0, "Could not read file")])
        return text, file_path

    default_filename = "configuration"


class DockerfileParser(BaseParser):
    """Extract images and security-relevant instructions from Dockerfiles."""

    name = "dockerfile"
    default_filename = "Dockerfile"
    file_extensions = (".dockerfile", "dockerfile")
    _instruction = re.compile(r"^([A-Z]+)\s*(.*)$", re.IGNORECASE)
    _known_instructions: ClassVar[set[str]] = {
        "ADD",
        "ARG",
        "CMD",
        "COPY",
        "ENTRYPOINT",
        "ENV",
        "EXPOSE",
        "FROM",
        "HEALTHCHECK",
        "LABEL",
        "MAINTAINER",
        "ONBUILD",
        "RUN",
        "SHELL",
        "STOPSIGNAL",
        "USER",
        "VOLUME",
        "WORKDIR",
    }

    def can_parse(self, file_path: str) -> bool:
        return self.supports_file(file_path)

    def parse(
        self, file_path: str | None = None, content: str | None = None
    ) -> ParseResult:
        if (
            content is None
            and file_path
            and not os.path.exists(file_path)
            and re.match(
                r"(?i)\s*(FROM|RUN|CMD|USER|EXPOSE|ENV|VOLUME|COPY|ADD)\s", file_path
            )
        ):
            content, file_path = file_path, self.default_filename
        result = self._content(file_path, content)
        if isinstance(result, ParseResult):
            return result
        text, filename = result
        resources: list[Resource] = []
        errors: list[Finding] = []
        for line_no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = self._instruction.match(line)
            if not match:
                errors.append(
                    self.error(filename, line_no, "Malformed Dockerfile instruction")
                )
                continue
            instruction, value = match.group(1).upper(), match.group(2).strip()
            if instruction == "FROM":
                image = next(
                    (part for part in value.split() if not part.startswith("--")),
                    "unknown-image",
                )
                if image == "unknown-image":
                    errors.append(
                        self.error(
                            filename, line_no, "FROM instruction is missing an image"
                        )
                    )
                    continue
                resources.extend(
                    [
                        self.normalize_resource(
                            "image", image, filename, line_no, evidence=line
                        ),
                        self.normalize_resource(
                            "container", image, filename, line_no, evidence=line
                        ),
                    ]
                )
            elif instruction == "USER":
                user = value.split()[0] if value else "unknown"
                resources.append(
                    self.normalize_resource(
                        "user" if user.lower() in ("root", "0") else "nonroot_user",
                        user,
                        filename,
                        line_no,
                        evidence=line,
                    )
                )
            elif instruction == "EXPOSE":
                for port in value.split():
                    resources.append(
                        self.normalize_resource(
                            "exposed_port", port, filename, line_no, evidence=line
                        )
                    )
            elif instruction == "VOLUME":
                paths = re.findall(r"['\"]([^'\"]+)['\"]", value)
                if not paths:
                    paths = value.strip("[]").split()
                for path in paths:
                    resources.append(
                        self.normalize_resource(
                            "volume", path.strip(","), filename, line_no, evidence=line
                        )
                    )
            elif instruction == "ENV":
                name = value.split("=", 1)[0].split()[0] if value else "unknown"
                resources.append(
                    self.normalize_resource(
                        "environment_variable", name, filename, line_no, evidence=line
                    )
                )
                if (
                    re.search(
                        r"(?:PASS(?:WORD)?|SECRET|TOKEN|API[_-]?KEY)",
                        name,
                        re.IGNORECASE,
                    )
                    and "=" in value
                ):
                    resources.append(
                        self.normalize_resource(
                            "secret", name, filename, line_no, evidence=line
                        )
                    )
            elif instruction in ("RUN", "CMD", "ENTRYPOINT", "COPY", "ADD"):
                resources.append(
                    self.normalize_resource(
                        "instruction",
                        instruction.lower(),
                        filename,
                        line_no,
                        evidence=line,
                    )
                )
            else:
                # Keep unfamiliar directives visible to generic rule checks.
                resources.append(
                    self.normalize_resource(
                        "instruction", line, filename, line_no, evidence=line
                    )
                )
                if instruction not in self._known_instructions:
                    errors.append(
                        self.error(
                            filename,
                            line_no,
                            f"Unsupported Dockerfile instruction: {instruction}",
                        )
                    )
        if not any(r.resource_type == "image" for r in resources) and text.strip():
            errors.append(self.error(filename, 1, "Dockerfile has no FROM instruction"))
        return ParseResult(resources, errors)

    def parse_string(self, content: str, file_path: str | None = None) -> ParseResult:
        return self.parse(file_path=file_path or self.default_filename, content=content)


class DockerComposeParser(BaseParser):
    """Parse Compose services, images, ports, volumes and security settings."""

    name = "docker-compose"
    default_filename = "docker-compose.yml"
    file_extensions = (".yml", ".yaml")

    def can_parse(self, file_path: str) -> bool:
        return self.supports_file(file_path)

    def parse(
        self, file_path: str | None = None, content: str | None = None
    ) -> ParseResult:
        if (
            content is None
            and file_path
            and not os.path.exists(file_path)
            and (
                "\n" in file_path
                or re.search(r"(?m)^\s*(services|version)\s*:", file_path)
            )
        ):
            content, file_path = file_path, self.default_filename
        result = self._content(file_path, content)
        if isinstance(result, ParseResult):
            return result
        text, filename = result
        resources: list[Resource] = []
        try:
            document = yaml.safe_load(text)
            if not isinstance(document, dict) or not isinstance(
                document.get("services"), dict
            ):
                raise TypeError("expected a mapping with a services mapping")
            if not document["services"]:
                raise ValueError("Compose file has no services")
            for name, config in document["services"].items():
                if not isinstance(config, dict):
                    raise TypeError(f"service {name!r} must be a mapping")
                resources.append(
                    self.normalize_resource(
                        "compose_service",
                        str(name),
                        filename,
                        evidence=yaml.safe_dump(config, sort_keys=True),
                    )
                )
                image = config.get("image")
                if isinstance(image, str):
                    resources.append(
                        self.normalize_resource(
                            "image",
                            image,
                            filename,
                            evidence=f"service {name}: image: {image}",
                        )
                    )
                if config.get("privileged") is True:
                    resources.append(
                        self.normalize_resource(
                            "container",
                            str(name),
                            filename,
                            evidence=f"service {name}: privileged: true",
                        )
                    )
                for port in config.get("ports", []) or []:
                    resources.append(
                        self.normalize_resource(
                            "exposed_port",
                            str(port),
                            filename,
                            evidence=f"service {name}: ports: {port}",
                        )
                    )
                for volume in config.get("volumes", []) or []:
                    source = str(volume).split(":", 1)[0]
                    resources.append(
                        self.normalize_resource(
                            "volume",
                            source,
                            filename,
                            evidence=f"service {name}: volumes: {volume}",
                        )
                    )
                if not config.get("deploy", {}).get("resources", {}).get("limits"):
                    resources.append(
                        self.normalize_resource(
                            "container",
                            str(name),
                            filename,
                            evidence=f"service {name}: resource limits missing",
                        )
                    )
            for category in ("networks", "volumes"):
                items = document.get(category, {}) or {}
                if isinstance(items, dict):
                    resources.extend(
                        self.normalize_resource(category[:-1], str(name), filename)
                        for name in items
                    )
            return ParseResult(resources)
        except (yaml.YAMLError, ValueError, AttributeError, TypeError) as exc:
            mark = getattr(exc, "problem_mark", None)
            line_number = getattr(mark, "line", 0) + 1
            return ParseResult(resources, [self.error(filename, line_number, str(exc))])

    def parse_string(self, content: str, file_path: str | None = None) -> ParseResult:
        return self.parse(file_path=file_path or self.default_filename, content=content)


class KubernetesParser(BaseParser):
    """Parse Kubernetes YAML documents and extract workload security evidence."""

    name = "kubernetes"
    default_filename = "manifest.yaml"
    file_extensions = (".yaml", ".yml")

    def can_parse(self, file_path: str) -> bool:
        return self.supports_file(file_path)

    def parse(
        self, file_path: str | None = None, content: str | None = None
    ) -> ParseResult:
        if (
            content is None
            and file_path
            and not os.path.exists(file_path)
            and (
                "\n" in file_path
                or re.search(r"(?m)^\s*(apiVersion|kind)\s*:", file_path)
            )
        ):
            content, file_path = file_path, self.default_filename
        result = self._content(file_path, content)
        if isinstance(result, ParseResult):
            return result
        text, filename = result
        resources: list[Resource] = []
        errors: list[Finding] = []
        try:
            for index, document in enumerate(yaml.safe_load_all(text), 1):
                if document is None:
                    continue
                if not isinstance(document, dict):
                    errors.append(
                        self.error(
                            filename, index, "Kubernetes document must be a mapping"
                        )
                    )
                    continue
                kind = str(document.get("kind", "")).lower()
                metadata = document.get("metadata") or {}
                name = (
                    str(metadata.get("name", f"k8s-document-{index}"))
                    if isinstance(metadata, dict)
                    else f"k8s-document-{index}"
                )
                if not kind:
                    errors.append(
                        self.error(
                            filename, index, "Kubernetes document is missing kind"
                        )
                    )
                    continue
                spec = document.get("spec") or {}
                pod_spec = (
                    spec.get("template", {}).get("spec", {})
                    if kind in ("deployment", "statefulset", "daemonset", "job")
                    and isinstance(spec, dict)
                    else spec
                )
                containers = (
                    pod_spec.get("containers", []) if isinstance(pod_spec, dict) else []
                )
                security_strings: list[str] = []
                if isinstance(containers, list):
                    for container in containers:
                        if not isinstance(container, dict):
                            continue
                        image = container.get("image")
                        if image:
                            resources.append(
                                self.normalize_resource(
                                    "image",
                                    str(image),
                                    filename,
                                    index,
                                    evidence=f"container {container.get('name', '')}: image: {image}",
                                )
                            )
                        context = container.get("securityContext") or {}
                        pod_context = (
                            pod_spec.get("securityContext") or {}
                            if isinstance(pod_spec, dict)
                            else {}
                        )
                        effective_context = (
                            {**pod_context, **context}
                            if isinstance(pod_context, dict)
                            and isinstance(context, dict)
                            else {}
                        )
                        container_signals: list[str] = []
                        for key in (
                            "runAsNonRoot",
                            "runAsUser",
                            "readOnlyRootFilesystem",
                            "allowPrivilegeEscalation",
                        ):
                            if key in effective_context:
                                container_signals.append(
                                    f"{key}: {effective_context[key]}"
                                )
                        if effective_context.get("privileged") is True:
                            container_signals.append("privileged: true")
                        capabilities = effective_context.get("capabilities")
                        if isinstance(capabilities, dict) and capabilities.get("add"):
                            container_signals.append(
                                f"capabilities add: {', '.join(map(str, capabilities['add']))}"
                            )
                        limits = container.get("resources") or {}
                        if not isinstance(limits, dict):
                            errors.append(
                                self.error(
                                    filename,
                                    index,
                                    f"resources for container {container.get('name', '')!r} must be a mapping",
                                )
                            )
                            limits = {}
                        if not limits.get("limits"):
                            container_signals.append("resource limits missing")
                        else:
                            container_signals.append("resource limits configured")
                        security_strings.extend(container_signals)
                        if not any(
                            signal.startswith(
                                (
                                    "runAsNonRoot:",
                                    "runAsUser:",
                                    "readOnlyRootFilesystem:",
                                )
                            )
                            for signal in container_signals
                        ):
                            container_signals.insert(
                                0, "No container security context detected"
                            )
                        resources.append(
                            self.normalize_resource(
                                "container",
                                str(container.get("name", name)),
                                filename,
                                index,
                                evidence="; ".join(container_signals),
                            )
                        )
                resource_type = (
                    "deployment"
                    if kind in ("deployment", "statefulset", "daemonset")
                    else kind
                )
                resources.append(
                    self.normalize_resource(
                        resource_type,
                        name,
                        filename,
                        index,
                        evidence="; ".join(security_strings)
                        or "No container security context or resource limits detected",
                    )
                )
            if not resources and not errors:
                errors.append(self.error(filename, 0, "No Kubernetes documents found"))
        except (yaml.YAMLError, AttributeError, TypeError) as exc:
            mark = getattr(exc, "problem_mark", None)
            line_number = getattr(mark, "line", 0) + 1
            errors.append(self.error(filename, line_number, str(exc)))
        return ParseResult(resources, errors)

    def parse_string(self, content: str, file_path: str | None = None) -> ParseResult:
        return self.parse(file_path=file_path or self.default_filename, content=content)


class TerraformParser(BaseParser):
    """Extract Terraform resource, variable and output blocks without execution."""

    name = "terraform"
    default_filename = "terraform.tf"
    file_extensions = (".tf",)
    _block = re.compile(
        r'\b(resource|variable|output|provider)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{',
        re.MULTILINE,
    )

    def can_parse(self, file_path: str) -> bool:
        return self.supports_file(file_path)

    def parse(
        self, file_path: str | None = None, content: str | None = None
    ) -> ParseResult:
        if (
            content is None
            and file_path
            and not os.path.exists(file_path)
            and re.search(r"\b(resource|variable|output|provider)\s+\"", file_path)
        ):
            content, file_path = file_path, self.default_filename
        result = self._content(file_path, content)
        if isinstance(result, ParseResult):
            return result
        text, filename = result
        resources: list[Resource] = []
        errors: list[Finding] = []
        # Remove comments and quoted strings before brace balancing.
        balance = 0
        quoted = False
        escaped = False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
                continue
            if char == '"':
                quoted = True
            elif char == "{":
                balance += 1
            elif char == "}":
                balance -= 1
                if balance < 0:
                    errors.append(self.error(filename, 1, "Unexpected closing brace"))
                    break
        if balance > 0:
            errors.append(self.error(filename, 1, "Unclosed Terraform block"))
        for match in self._block.finditer(text):
            kind, first, second = match.groups()
            name = second or first
            resource_type = (
                f"terraform_{first}" if kind == "resource" else f"terraform_{kind}"
            )
            resources.append(
                self.normalize_resource(
                    resource_type,
                    name,
                    filename,
                    text.count("\n", 0, match.start()) + 1,
                    evidence=text[match.start() : match.start() + 300],
                )
            )
        if text.strip() and not resources and not errors:
            errors.append(
                self.error(filename, 1, "No supported Terraform blocks found")
            )
        return ParseResult(resources, errors)

    def parse_string(self, content: str, file_path: str | None = None) -> ParseResult:
        return self.parse(file_path=file_path or self.default_filename, content=content)
