"""Regression coverage for supported parser behavior and normalized output."""

from src.parsers.base import (
    DockerComposeParser,
    DockerfileParser,
    KubernetesParser,
    TerraformParser,
)


def test_dockerfile_extracts_security_resources() -> None:
    result = DockerfileParser().parse(
        content='FROM python:3.11-slim\nUSER root\nEXPOSE 22\nVOLUME ["/etc"]\n'
    )
    assert not result.errors
    assert {r.resource_type for r in result.resources} >= {
        "image",
        "container",
        "user",
        "exposed_port",
        "volume",
    }
    assert all(
        r.filename == "Dockerfile" and r.resource_id == f"{r.resource_type}:{r.name}"
        for r in result.resources
    )


def test_compose_reads_file_and_extracts_service_signals() -> None:
    content = """services:
  web:
    image: nginx:latest
    privileged: true
    ports: [\"80:80\"]
    volumes: [\"/etc:/host-etc\"]
"""
    result = DockerComposeParser().parse(content=content)
    assert not result.errors
    assert {r.resource_type for r in result.resources} >= {
        "compose_service",
        "image",
        "container",
        "exposed_port",
        "volume",
    }
    assert any("privileged: true" in r.evidence for r in result.resources)


def test_kubernetes_reads_all_documents() -> None:
    content = """apiVersion: v1
kind: Pod
metadata: {name: first}
spec:
  containers:
    - name: app
      image: example/app:1
      securityContext: {runAsNonRoot: true}
      resources: {limits: {cpu: \"1\", memory: 1Gi}}
---
apiVersion: v1
kind: Service
metadata: {name: second}
"""
    result = KubernetesParser().parse(content=content)
    assert not result.errors
    assert {
        r.name for r in result.resources if r.resource_type in ("pod", "service")
    } == {"first", "second"}
    assert any(
        r.resource_type == "image" and r.name == "example/app:1"
        for r in result.resources
    )


def test_terraform_extracts_resources_and_reports_unclosed_blocks() -> None:
    result = TerraformParser().parse(
        content='resource "aws_instance" "web" { ami = "ami-123" }'
    )
    assert not result.errors
    assert result.resources[0].resource_type == "terraform_aws_instance"
    malformed = TerraformParser().parse(
        content='resource "aws_instance" "web" { ami = "ami-123"'
    )
    assert malformed.has_errors
    assert "Unclosed" in malformed.errors[0].description


def test_malformed_yaml_returns_parse_error_without_raising() -> None:
    compose = DockerComposeParser().parse(content="services:\n  app: [broken\n")
    kubernetes = KubernetesParser().parse(content="kind: [broken\n")
    assert compose.has_errors
    assert kubernetes.has_errors


def test_project_fixtures_parse_or_return_errors() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    fixtures = root / "fixtures"
    cases = [
        (DockerfileParser(), fixtures / "valid" / "dockerfile_valid.py"),
        (DockerComposeParser(), fixtures / "valid" / "docker-compose.yml"),
        (KubernetesParser(), fixtures / "valid" / "kubernetes.yaml"),
        (TerraformParser(), fixtures / "valid" / "main.tf"),
        (
            DockerfileParser(),
            fixtures / "intentional_vulns" / "dockerfile_root_user.py",
        ),
        (
            KubernetesParser(),
            fixtures / "intentional_vulns" / "kubernetes_no_security_context.yaml",
        ),
        (
            TerraformParser(),
            fixtures / "intentional_vulns" / "terraform_unpinned_image.tf",
        ),
    ]
    for parser, path in cases:
        parsed = parser.parse(file_path=str(path))
        assert parsed.resources or parsed.errors, path
    for parser, path in (
        (DockerfileParser(), fixtures / "invalid" / "dockerfile_malformed.py"),
        (DockerComposeParser(), fixtures / "invalid" / "docker-compose-malformed.yml"),
        (KubernetesParser(), fixtures / "invalid" / "kubernetes-malformed.yaml"),
        (TerraformParser(), fixtures / "invalid" / "main-invalid.tf"),
    ):
        assert parser.parse(file_path=str(path)).has_errors
