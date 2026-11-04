# Phase 2 Requirements Checklist

| Requirement | Current status and limitation |
|---|---|
| Dockerfile parsing | Implemented for a useful subset of instructions. This is extraction, not complete Dockerfile validation. |
| Docker Compose | Implemented for services, images, ports, volumes, networks, and selected security signals using safe YAML loading. |
| Kubernetes YAML | Implemented for multi-document manifests and basic workload/image/security-context evidence. It is not full schema validation. |
| Terraform | Regex-based extraction of resource, variable, output, and provider blocks with basic brace checks. It is not an HCL parser and does not validate Terraform semantics. |
| Error handling | YAML and simple structural errors are returned in `ParseResult.errors`; behavior is covered by parser tests, pending a successful test run. |
| Directory scanning | Not implemented. Parsers accept one file or an in-memory string; no scanner orchestrates directories. |

Valid, malformed, and intentionally vulnerable samples are kept under `fixtures/`. Implementation details are in `src/parsers/base.py`; tests are in `tests/test_parsers.py`.
