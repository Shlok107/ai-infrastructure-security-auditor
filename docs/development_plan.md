# Academic Project Development Plan

## Goal and current baseline

The project's long-term goal is an explainable infrastructure security auditor that parses infrastructure-as-code, models relationships, identifies risks, and presents evidence-backed remediation guidance. The current baseline parses selected constructs from Dockerfiles, Docker Compose, Kubernetes YAML, and Terraform; normalizes resources; and evaluates a deterministic catalog of ten rules.

The project should remain explicit about the difference between observed configuration evidence, deterministic rule findings, inferred relationships, and AI-generated narrative. AI must not become the source of truth for detection. Inputs must not be executed or deployed as part of analysis.

## Roadmap

| Stage | Planned work | Exit evidence |
|---|---|---|
| 1. Foundation | Mature package setup, model tests, consistent errors, installation and test workflow | Fresh environment installs and passes tests |
| 2. Parsing | Expand parser coverage, source locations, malformed-input handling, and documented format limits | Representative valid, invalid, and edge-case fixtures per format |
| 3. Baseline scanning | Improve rule evidence, confidence, false-positive controls, and coverage | Deterministic positive and negative cases for each supported rule |
| 4. Resource graph | Build typed, provenance-bearing relationships from parsed resources | Multi-file fixture yields testable, traceable nodes and edges |
| 5. Context and attack paths | Add bounded, auditable reasoning over graph facts and explicit assumptions | Reproducible scenarios with traceable intermediate reasoning |
| 6. Prioritization | Rank findings and sequence remediation with transparent factors | Stable rankings and dependency-aware actions with tested tie behavior |
| 7. AI-assisted explanations | Optionally explain grounded findings with schema validation and deterministic fallback | Model failures preserve deterministic results; narrative adds no unsupported findings |
| 8. CLI and reporting | Add file/directory workflow, stable exit codes, human-readable and JSON reports | End-to-end test demonstrates documented CLI behavior |
| 9. Evaluation | Build a licensed, labeled corpus and measure precision, recall, parse coverage, and runtime | Reproducible results with stated threats to validity |
| 10. Hardening and demonstration | Review input limits, privacy, dependencies, docs, and integrated workflow | Fresh checkout runs a documented, evidence-backed demonstration |

## Design principles

- Prefer a small, tested deterministic baseline before adding model-assisted features.
- Preserve source evidence and distinguish direct findings from inference.
- Keep parsing safe: do not execute Terraform, build containers, apply Kubernetes resources, or run untrusted project code.
- Treat parser support as partial until meaningful edge cases and tests establish its limits.
- Send only approved structured evidence to any future external AI provider; document privacy implications and redact secrets.
- Measure detection and reasoning quality using labeled inputs; do not claim unmeasured performance.

## Academic evaluation

Future evaluation should document the provenance, version, and licensing constraints of benchmark materials. The test corpus should include secure examples, seeded vulnerabilities, and multi-resource scenarios. Report precision, recall, F1 for labeled rules, parsing coverage and failure rate, relationship correctness, attack-path validity, remediation ranking quality, and runtime where applicable. Separate measured results from expected benefits and describe limitations and threats to validity.

## Current limitations

Directory scanning, a CLI, graph construction, attack-path reasoning, prioritization, AI explanations, generated reports, and benchmark evaluation are not implemented. The current parser and rule layer remains a prototype. See the [README](../README.md#current-implementation-status) for the feature status and user-facing scope.
