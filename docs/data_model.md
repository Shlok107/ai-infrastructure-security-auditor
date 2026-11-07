# Data Model

The schemas are defined in `src/models.py` with Pydantic 2. They form a prototype shared representation for extracted configuration and rule findings.

| Model | Purpose |
|---|---|
| `Severity` | String-valued `critical`, `high`, `medium`, `low`, and `info` levels |
| `Resource` | Normalized ID, type, name, source filename, optional line, and evidence text |
| `Evidence` | Source file, optional source line, snippet, and optional position mapping |
| `Finding` | Rule identity and title, severity, confidence, affected resource, evidence, description, remediation text, and references |
| `Rule` | Basic Pydantic rule schema with ID, title, severity, resource types, and active flag |
| `RemediationAction` | Proposed action schema; no remediation planner currently consumes it |
| `Relationship` | Typed relationship schema intended for future graph modeling; no graph builder currently consumes it |

The operational rule format used by the current engine is a dataclass in `src/rules/base_rule.py`; it is distinct from the Pydantic `Rule` schema. Models are frozen. The schemas may change as parsing and orchestration mature.
