# AI Infrastructure Security Auditor

An academic Python project that parses selected infrastructure configuration formats, normalizes security-relevant resources, and evaluates them with deterministic rules. The project is AI-oriented in its longer-term direction; the current implementation does not use an AI model.

## Problem

Infrastructure configuration can expose services, grant containers excessive privileges, embed sensitive values, or omit safeguards. Reviewing files in different formats by hand makes these issues harder to spot consistently. This project explores a common representation and a traceable rule-based baseline for identifying selected risks.

## Objectives

- Parse selected infrastructure files without executing or deploying them.
- Normalize extracted resources into shared Pydantic models.
- Evaluate evidence with deterministic security rules and return structured findings.
- Provide a foundation for future contextual reasoning, attack-path analysis, AI-assisted explanations, and remediation recommendations.

## Implemented features

- Dockerfile extraction for images and selected instructions, users, ports, volumes, and environment variables.
- Docker Compose extraction for services, images, ports, volumes, networks, and selected security settings.
- Kubernetes YAML extraction across single- and multi-document manifests, including selected workload, image, and security-context evidence.
- Basic regex-based Terraform extraction for resource, variable, output, and provider blocks.
- Shared resource, evidence, finding, rule, and severity models.
- Ten deterministic baseline checks for root users, privileged containers, sensitive mounts, risky ports, missing Kubernetes security-context restrictions, permissive capabilities, embedded secrets, resource limits, unrestricted Terraform security-group ingress, and mutable image references.
- Structured parser errors for supported input parsing failures.
- Valid, malformed, and intentionally vulnerable example fixtures.

Parser and rule coverage is a prototype baseline; it is not full language validation or a comprehensive security assessment. See [limitations](#limitations) and [current status](#current-implementation-status).

## Supported configuration formats

| Format | Current support | Important scope limit |
|---|---|---|
| Dockerfile | Selected instructions and resource evidence | Not a complete Dockerfile parser or validator |
| Docker Compose | YAML service configuration and selected fields | Not full Compose schema validation |
| Kubernetes YAML | Selected resources; multi-document streams | Not Kubernetes API schema validation |
| Terraform | Regex-based resource, variable, output, and provider block extraction | Not an HCL parser; Terraform semantics are not validated |

## Architecture overview

Format-specific parser classes in `src/parsers/base.py` produce `Resource` objects and parse errors. Pydantic schemas are defined in `src/models.py`. The rule definitions in `src/rules/rules_catalog.py` are evaluated by `RuleEngine` in `src/rules/base_rule.py`, which returns sorted, deduplicated `Finding` objects. Callers currently compose parsing and rule evaluation themselves; directory-wide scan orchestration is not implemented.

See [architecture and repository layout](docs/architecture.md), [data model](docs/data_model.md), and [development plan](docs/development_plan.md).

## Technology stack

- Python 3.11 or later
- Pydantic 2
- PyYAML
- pytest and pytest-mock for development
- setuptools with PEP 621 metadata
- Ruff, Mypy, and Black as development tools

## Repository structure

```text
.
├── docs/                       # Architecture, models, error handling, roadmap
├── fixtures/
│   ├── valid/
│   ├── invalid/
│   └── intentional_vulns/
├── src/
│   ├── models.py
│   ├── parsers/                 # Dockerfile, Compose, Kubernetes, Terraform
│   ├── rules/                   # Rule model, engine, baseline catalog
│   ├── scanner/                 # Reserved; orchestration not implemented
│   ├── graph/                   # Reserved; graph construction not implemented
│   ├── reasoning/               # Reserved; reasoning not implemented
│   ├── explanations/            # Reserved; AI explanations not implemented
│   └── reporting/               # Reserved; report generation not implemented
├── tests/                       # Parser and rule tests
├── LICENSE
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```

The source packages marked reserved currently contain no functional implementation. Example configurations are organized in [fixtures/](fixtures/).

## Installation

From the repository root, create and activate a virtual environment, then install the project with development dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Example infrastructure configurations

The parser accepts configuration text or file paths. These abbreviated examples show the input formats; fuller samples are in the linked fixture directories.

Dockerfile:

```dockerfile
FROM python:3.11-slim
USER appuser
EXPOSE 8080
```

Docker Compose:

```yaml
services:
  web:
    image: nginx:1.27
    ports:
      - "8080:80"
```

Also see the [valid fixtures](fixtures/valid/) and [intentionally vulnerable fixtures](fixtures/intentional_vulns/).

## Example: parse and evaluate rules

There is no installed command-line interface. Use the parser and rule engine from Python:

```python
from src.parsers.base import DockerfileParser
from src.rules.base_rule import RuleEngine

parsed = DockerfileParser().parse(
    content="FROM python:3.11-slim\nUSER root\n"
)

if parsed.errors:
    for error in parsed.errors:
        print(error.title, error.evidence)

findings = RuleEngine().scan(parsed.resources)
for finding in findings:
    print(finding.severity, finding.rule_id, finding.remediation)
```

Parser methods accept either `file_path="path/to/config"` or in-memory `content`. A `ParseResult` contains `resources` and `errors`; the caller should inspect both. Sample inputs include [Docker Compose](fixtures/valid/docker-compose.yml), [multi-document Kubernetes YAML](fixtures/valid/kubernetes.yaml), and [Terraform](fixtures/valid/main.tf). The [intentional vulnerability fixtures](fixtures/intentional_vulns/) demonstrate selected seeded conditions.

## Tests and development checks

Run the automated test suite from the repository root:

```powershell
python -m pytest -v
```

Optional development checks are available after installing `.[dev]`:

```powershell
ruff check src tests
mypy src
```

## Current implementation status

| Area | Status |
|---|---|
| Configuration parsing | Implemented for selected constructs in four formats |
| Resource modeling | Implemented with Pydantic models |
| Rule evaluation | Implemented as a deterministic baseline of ten rules |
| Parse error reporting | Implemented for supported parsing and basic structural errors |
| Directory-wide auditing and end-to-end orchestration | Not implemented |
| CLI | Not implemented |
| Graph-based reasoning and attack-path analysis | Not implemented |
| AI-powered explanations | Not implemented; no AI service is called |
| Automated remediation recommendations | Not implemented as a workflow; individual findings include remediation text |
| Complete security audit reporting | Not implemented |

The architecture is intended to evolve toward relationships between resources, auditable contextual reasoning, attack-path analysis, evidence-grounded AI-assisted explanations, and prioritized remediation recommendations. These are future enhancements, not current capabilities. The detailed academic roadmap is in [docs/development_plan.md](docs/development_plan.md).

## Limitations

- Parsing extracts selected evidence and does not fully validate any supported language or schema.
- Terraform parsing is regex-based, so nested or unusual HCL constructs may not be handled correctly.
- Rules are heuristic and depend on parser evidence; they can miss issues or produce incorrect findings.
- There is no directory scanner, CLI, graph, attack-path engine, AI integration, or report generator.
- Findings should be reviewed against the source configuration and should not be treated as a complete security assessment.

## License

This project is distributed under the [MIT License](LICENSE).
