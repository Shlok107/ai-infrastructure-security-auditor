# Architecture and Repository Layout

## Current data flow

The implemented flow is deliberately small and caller-driven:

1. A caller passes a file path or configuration string to a parser in `src/parsers/base.py`.
2. The parser extracts selected constructs into `Resource` models and returns parse errors in a `ParseResult`.
3. A caller passes the resources to `RuleEngine` in `src/rules/base_rule.py`.
4. The engine runs the baseline catalog in `src/rules/rules_catalog.py` and returns structured `Finding` models.

The parser uses PyYAML safe loading for YAML inputs. It does not execute project configuration or deploy infrastructure. No directory scanner or command-line entry point currently joins these steps into an application workflow.

## Module responsibilities

| Path | Responsibility and status |
|---|---|
| `src/models.py` | Pydantic resource, evidence, finding, rule, severity, relationship, and remediation-action schemas |
| `src/parsers/base.py` | Shared parser helpers and current Dockerfile, Compose, Kubernetes, and Terraform parsers |
| `src/rules/base_rule.py` | Operational rule definition and deterministic evaluation engine |
| `src/rules/rules_catalog.py` | Ten baseline security checks |
| `src/scanner/` | Reserved package; orchestration and CLI are not implemented |
| `src/graph/` | Reserved package; graph construction is not implemented |
| `src/reasoning/` | Reserved package; contextual and attack-path reasoning are not implemented |
| `src/explanations/` | Reserved package; explanation and AI integration are not implemented |
| `src/reporting/` | Reserved package; audit report generation is not implemented |
| `tests/` | Parser and rule tests |
| `fixtures/` | Valid, invalid, and intentionally vulnerable example configurations |

## Repository layout

```text
docs/       Supporting technical documentation and project plan
fixtures/   valid/, invalid/, intentional_vulns/
src/        Python package and implemented parser/rule modules
tests/      Automated tests kept separate from application code
```

See [data_model.md](data_model.md) for model fields and [logging_and_errors.md](logging_and_errors.md) for current error behavior and future logging constraints.
