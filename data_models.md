# Data Models

The Pydantic v2 models are implemented in `src/models.py`.

- `Severity`: string enum with `critical`, `high`, `medium`, `low`, and `info` values.
- `Resource`: normalized ID, type, name, filename, optional line number, and evidence text.
- `Evidence`: source file, optional source line, snippet, and optional position mapping.
- `Finding`: rule ID, title, severity, confidence, affected resource, evidence, description, remediation, and references.
- `Rule`: basic Pydantic rule schema with ID, title, severity, resource types, and active flag. The operational, callable rule format used by the engine is a dataclass in `src/rules/base_rule.py`.
- `RemediationAction` and `Relationship`: data structures intended for future remediation planning and graph modeling; no workflow currently consumes them.

All models are frozen. These schemas are a prototype and may evolve as parser and scanner coverage grows.
