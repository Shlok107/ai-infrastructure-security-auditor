# AI Infrastructure Security Auditor

An academic project for inspecting infrastructure-as-code and surfacing security-relevant configuration. The current implementation provides parsers that normalize selected resources and a deterministic rule engine that evaluates those resources. It does not deploy infrastructure or call an AI service.

## Problem

Infrastructure configuration can expose services, run containers with excess privilege, embed secrets, or omit important safeguards. Reviewing multiple formats by hand makes these issues easy to miss.

## Objectives

- Parse Dockerfiles, Docker Compose YAML, Kubernetes YAML, and Terraform files without executing them.
- Normalize extracted resources into a shared data model.
- Evaluate deterministic security rules and return findings with severity and remediation guidance.
- Build toward relationship modeling, attack-path analysis, assisted explanations, and reports in later phases.

## Implemented features

- Dockerfile extraction for base images, users, exposed ports, volumes, environment variables, and common instructions.
- Docker Compose extraction for services, images, ports, volumes, networks, and basic service security signals.
- Kubernetes single and multi-document YAML extraction, including workload image and security-context evidence.
- Terraform resource, variable, output, and provider block extraction with basic structural error reporting.
- Versioned rule definitions and a rule engine with stable sorting and deduplication.
- Pydantic resource and finding models.

## Not implemented yet

The `src/graph`, `src/reasoning`, `src/explanations`, `src/reporting`, and `src/scanner` packages are placeholders. There is no end-to-end scanner, command-line interface, attack-path analysis, AI explanation service, or report generator yet. Parser and rule coverage is intentionally a baseline; this is not a complete validator for any of the source languages.

## Architecture

Configuration files are parsed into `Resource` objects in `src/parsers/base.py`. The rule catalog in `src/rules/rules_catalog.py` defines checks, and `RuleEngine` evaluates resources and returns `Finding` objects. Models live in `src/models.py`. Graph reasoning, explanations, reporting, and a scanner orchestration layer are future work.

## Technology

- Python 3.11 or later
- Pydantic 2
- PyYAML
- pytest
- setuptools with PEP 621 project metadata

## Project structure

```text
src/
  models.py
  parsers/       # Dockerfile, Compose, Kubernetes, Terraform
  rules/         # Rule model, engine, and baseline catalog
  graph/         # Planned
  reasoning/     # Planned
  explanations/  # Planned
  reporting/     # Planned
  scanner/       # Planned
tests/           # Automated rule tests and parser coverage
fixtures/        # Valid, malformed, and intentionally vulnerable examples
```

## Installation

Create and activate a virtual environment, then install the project and development tools:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Usage

There is no installed CLI yet. Parsers and the rule engine can be used from Python:

```python
from src.parsers.base import DockerfileParser
from src.rules.base_rule import RuleEngine

parsed = DockerfileParser().parse(content="FROM python:3.11-slim\nUSER root\n")
findings = RuleEngine().scan(parsed.resources)

for finding in findings:
    print(finding.severity, finding.rule_id, finding.remediation)
```

Parser instances also accept `file_path="path/to/config"`. A `ParseResult` contains normalized `resources` and parser `errors`; callers should inspect both before evaluating findings. For example, start with `fixtures/valid/docker-compose.yml`, `fixtures/valid/kubernetes.yaml`, or `fixtures/valid/main.tf`. Intentionally vulnerable samples are under `fixtures/intentional_vulns/`.

## Tests

```powershell
python -m pytest -v
```

The tests focus on deterministic rule evaluation and fixture-driven security cases. Parser-specific regression coverage is being expanded alongside the parser implementation.

## Project status and roadmap

The data model and baseline rule layer are implemented. Parser support is intentionally partial and should be treated as extraction for security checks, not full Docker, Compose, Kubernetes, or Terraform language validation. See [plan.md](plan.md) and the phase checklists for planned work. In brief, next steps include broader parser tests, a scanner orchestration layer, graph relationships, explainable attack-path reasoning, optional AI-assisted explanations grounded in findings, and machine-readable reports.

## License

No license file is currently included. Add an actual license before distributing the project under a specific license.
