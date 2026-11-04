# Repository Structure

This is the current checked-in layout. Packages marked “planned” currently contain only `__init__.py` files.

```text
src/
  __init__.py
  models.py
  parsers/
    __init__.py
    base.py                 # Current Dockerfile, Compose, Kubernetes, Terraform parsers
  rules/
    __init__.py
    base_rule.py            # Rule model and evaluation engine
    rules_catalog.py        # Baseline deterministic checks
  scanner/                  # Planned orchestration and CLI
  graph/                    # Planned resource relationship modeling
  reasoning/                # Planned attack-path reasoning
  explanations/             # Planned finding explanations
  reporting/                # Planned audit reports
tests/
  test_rules.py
  test_parsers.py
fixtures/
  valid/
  invalid/
  intentional_vulns/
```

The four parser implementations currently share `src/parsers/base.py`. The rule engine is in `src/rules/base_rule.py`; rule definitions are in `src/rules/rules_catalog.py`. There is no `src/scanner/engine.py`, CLI, graph builder, reasoning engine, explanation adapter, or report generator yet.
