# AI Infrastructure Configuration Auditor --- Implementation Plan

## Project Goal

Build an explainable security-auditing system that analyzes
infrastructure-as-code files, identifies configuration risks, models
relationships between resources, traces plausible attack paths, and
recommends prioritized remediation steps.

The repository starts empty. Implement the project incrementally,
keeping every phase runnable and testable before moving to the next.

## Scope and Implementation Principles

-   **Start with a reliable baseline:** implement deterministic security
    checks before adding AI-generated explanations.
-   **Use structured findings:** every finding should include a stable
    rule ID, severity, affected file/resource, evidence, explanation,
    and remediation.
-   **Make reasoning traceable:** distinguish directly detected
    misconfigurations from inferred relationships and potential attack
    paths.
-   **Use AI as an assistant, not the source of truth:** AI explanations
    must be grounded in scanner evidence; do not let a language model
    invent findings or override rule results.
-   **Keep the first version local and reproducible:** provide a
    command-line interface and machine-readable output before building a
    web UI or CI integrations.
-   **Handle input safely:** parse files without deploying
    infrastructure, executing configuration, or running untrusted
    project code.

## Phase 1 --- Repository Foundation and Project Setup

### Objectives

Create a clean, maintainable foundation for the project.

### Tasks

-   Choose and document the implementation stack. Recommended default:
    Python, with `pytest` for tests and typed data models for findings
    and infrastructure resources.
-   Create the initial repository structure, for example:
    -   `src/` --- application code
    -   `src/parsers/` --- format-specific parsers
    -   `src/scanner/` --- security rules and orchestration
    -   `src/graph/` --- knowledge graph and graph algorithms
    -   `src/reasoning/` --- rule chaining and attack-path analysis
    -   `src/explanations/` --- evidence-grounded explanation and
        remediation
    -   `src/reporting/` --- report generation
    -   `tests/` --- unit, integration, and fixture tests
    -   `fixtures/` --- safe sample configurations, including
        intentionally vulnerable examples
    -   `docs/` --- architecture, supported rules, and evaluation notes
-   Add dependency management, formatting/linting configuration,
    `.gitignore`, and a README.
-   Define common data models for resources, relationships, rules,
    findings, evidence, severity, and remediation actions.
-   Establish structured logging and consistent error handling.

### Deliverables

-   Runnable project skeleton
-   Documented setup and test commands
-   Initial data-model tests

### Exit Criteria

A fresh checkout can install dependencies and run the test suite
successfully.

## Phase 2 --- Configuration Input and Parsing

### Objectives

Read supported infrastructure configuration formats and normalize them
into a common representation.

### Tasks

-   Implement parsers for:
    -   Dockerfiles
    -   Docker Compose YAML
    -   Kubernetes YAML manifests, including multi-document files
    -   Terraform configuration files
-   Validate input files and report parse errors with file and line
    context where available.
-   Normalize parsed data into resource types and attributes without
    discarding source locations.
-   Support directories and individual files; ignore common
    generated/vendor directories by default.
-   Define explicit behavior for unsupported files, malformed YAML,
    duplicate resources, and partial parse failures.
-   Add fixtures for valid, malformed, and edge-case configurations.
-   Do not execute Terraform, build containers, or apply Kubernetes
    resources.

### Deliverables

-   Format-specific parsers
-   Normalized resource representation
-   Parser documentation and tests

### Exit Criteria

Representative fixtures from every supported format parse into
normalized resources with source references and useful errors for
invalid input.

## Phase 3 --- Baseline Rule-Based Security Scanner

### Objectives

Deliver useful, deterministic security findings before implementing
advanced reasoning.

### Tasks

-   Define a versioned rule format with:
    -   Rule ID and title
    -   Description and rationale
    -   Severity and confidence
    -   Applicable resource types
    -   Detection logic
    -   Evidence requirements
    -   Remediation guidance
    -   References to relevant security guidance where available
-   Implement an initial, documented set of high-value checks, such as:
    -   Containers configured to run as root or without an explicit
        non-root user
    -   Privileged containers
    -   Sensitive host-path mounts or excessive host access
    -   Broad or risky port exposure
    -   Kubernetes workloads missing relevant security-context
        restrictions
    -   Containers configured with overly permissive capabilities
    -   Secrets embedded directly in configuration
    -   Missing or risky resource limits where applicable
    -   Terraform security-group rules allowing unrestricted ingress on
        sensitive ports
    -   Unpinned or mutable container image references, reported with
        appropriate context
-   Avoid claiming a risk exists when the required evidence is absent;
    use an explicit `unknown` or `not assessed` state where needed.
-   Assign severity consistently and document the limitations of each
    rule.
-   Provide deterministic unit tests for both positive and negative
    cases.

### Deliverables

-   Rule engine
-   Initial security rule pack
-   Findings in a stable machine-readable schema

### Exit Criteria

The scanner detects seeded issues, avoids known false positives in
negative fixtures, and produces reproducible results.

## Phase 4 --- Knowledge Graph Construction

### Objectives

Represent infrastructure resources and their relationships so that risks
can be assessed beyond isolated file-level checks.

### Tasks

-   Build a graph from normalized resources.
-   Define node types such as container, image, service, workload, pod,
    namespace, network/security group, volume, secret reference, and
    cloud resource when supported by the input.
-   Define typed edges such as `exposes`, `mounts`, `runs_as`,
    `uses_image`, `belongs_to`, `references`, and `allows_traffic_to`.
-   Preserve source-file and source-location references on nodes and
    edges.
-   Track provenance and confidence for inferred relationships.
-   Make graph construction deterministic and provide graph validation
    utilities.
-   Start with a lightweight in-process graph representation; introduce
    a graph database only if scale or requirements justify it.

### Deliverables

-   Graph builder and documented graph schema
-   Graph inspection/export support
-   Tests for node and edge creation

### Exit Criteria

A multi-file fixture produces the expected graph, and every inferred
relationship can be traced to its source evidence.

## Phase 5 --- Rule Chaining, Graph Reasoning, and Attack-Path Analysis

### Objectives

Combine individual findings and graph relationships to identify
multi-step risks.

### Tasks

-   Implement transparent forward chaining for rules that infer
    consequences from known facts.
-   Implement backward chaining to investigate whether a defined
    high-level risk can be supported by available facts.
-   Keep the rule premises, intermediate facts, and resulting
    conclusions in an auditable reasoning trace.
-   Add attack-path analysis for carefully defined scenarios, such as
    externally reachable services connected to workloads with excessive
    privileges or sensitive mounts.
-   Use bounded graph traversal and explicit assumptions to prevent
    unbounded or misleading conclusions.
-   Add heuristic search only where it serves a defined purpose, such as
    ranking candidate paths; document the heuristic and its limitations.
-   Separate confirmed configuration issues from possible attack paths
    and inferred risks.
-   Include tests for multi-step reasoning, cycles, missing facts, and
    path-ranking behavior.

### Deliverables

-   Reasoning engine
-   Attack-path representation and ranking
-   Explanation traces for inferred risks

### Exit Criteria

Known scenarios produce expected, reproducible reasoning traces; the
system does not present speculative paths as confirmed exploitation.

## Phase 6 --- Risk Prioritization and Remediation Planning

### Objectives

Turn findings into an actionable, ordered remediation plan.

### Tasks

-   Create a documented prioritization model using factors such as
    severity, confidence, exposure, asset sensitivity, and graph
    connectivity.
-   Keep raw severity separate from calculated priority so users can
    understand why a finding ranks highly.
-   Identify related findings and avoid duplicating the same underlying
    issue across reports.
-   Model remediation actions with affected resources, dependencies,
    expected risk reduction, and potential operational impact where
    evidence supports it.
-   Produce a proposed remediation sequence that respects dependencies
    and explains the reason for each step.
-   Do not claim the sequence is globally optimal unless that property
    has been established; label heuristic results accordingly.
-   Add tests for ranking, ties, duplicate findings, and dependency
    ordering.

### Deliverables

-   Prioritization logic
-   Remediation-plan generator
-   Explanation of priority and ordering

### Exit Criteria

Given the same input, the system produces a stable, evidence-backed
priority ranking and a defensible remediation sequence.

## Phase 7 --- AI-Assisted Explanations

### Objectives

Use AI to make findings easier to understand without weakening
deterministic detection.

### Tasks

-   Define an explanation interface so the core scanner works even when
    no model/API is configured.
-   Supply the model only with structured findings, relevant graph
    context, reasoning traces, and approved remediation guidance.
-   Request concise explanations of the root cause, practical impact,
    supporting evidence, and suggested fix.
-   Require output to conform to a schema and validate it before
    inclusion in reports.
-   Prevent the model from adding unsupported vulnerabilities, inventing
    evidence, or silently changing severity.
-   Provide a deterministic fallback explanation if the model is
    unavailable, returns invalid output, or exceeds configured limits.
-   Document data sent to any external AI provider and keep secrets out
    of logs.
-   Test invalid responses, unavailable providers, and
    prompt-injection-like text embedded in scanned files.

### Deliverables

-   Optional AI explanation adapter
-   Schema validation and fallback behavior
-   Documentation for configuration, privacy, and limitations

### Exit Criteria

AI explanations are grounded in scanner evidence, failures do not break
auditing, and users can distinguish rule results from generated
narrative.

## Phase 8 --- CLI and Reporting

### Objectives

Make the auditor usable end to end.

### Tasks

-   Implement a command-line interface to scan a file or directory.
-   Support selecting output format, severity threshold, rule
    exclusions, and optional AI explanations.
-   Produce human-readable terminal output and JSON reports; add
    Markdown or HTML output if time permits.
-   Include summary counts, findings, evidence, affected resources,
    reasoning traces, attack paths, and remediation steps.
-   Return documented exit codes suitable for scripts and CI pipelines.
-   Ensure output is stable enough for automated comparison and avoid
    leaking secret values in reports.
-   Add end-to-end tests for successful scans, parse failures, and
    findings that should fail a configured threshold.

### Deliverables

-   Working CLI
-   JSON reporting and readable summary
-   Usage documentation and example commands

### Exit Criteria

A user can run one command against sample infrastructure and receive a
useful, reproducible audit report.

## Phase 9 --- Evaluation and Benchmarking

### Objectives

Measure detection quality, reasoning quality, and practical remediation
usefulness.

### Tasks

-   Select and document public cloud/container security benchmark
    material and open-source infrastructure repositories that can
    legally be used for evaluation.
-   Build a labeled test corpus containing secure examples,
    intentionally vulnerable examples, and multi-file scenarios.
-   Record the source, version, licensing constraints, and expected
    findings for each evaluation sample.
-   Compare baseline detection with established tools where practical,
    using the same inputs and clearly documenting differences in scope.
-   Measure:
    -   Precision, recall, and F1 score for supported, labeled rules
    -   False-positive and false-negative examples
    -   Parse coverage and failure rate
    -   Correctness of graph relationships on labeled fixtures
    -   Attack-path validity against manually specified scenarios
    -   Remediation ranking quality against documented criteria or
        expert review
    -   Runtime and resource usage on representative projects
-   Separate measured results from expected benefits; do not fabricate
    benchmark numbers.
-   Record limitations, unsupported configurations, and threats to
    validity.

### Deliverables

-   Reproducible evaluation scripts
-   Dataset manifest and labeled expected results
-   Results table and evaluation report

### Exit Criteria

The evaluation can be rerun, reported metrics are traceable to data, and
comparisons clearly state their limitations.

## Phase 10 --- Hardening, Documentation, and Final Demonstration

### Objectives

Prepare a dependable project demonstration and final submission.

### Tasks

-   Add integration tests across parsing, scanning, graph building,
    reasoning, prioritization, and reporting.
-   Review exception handling, dependency versions, file-size limits,
    performance, and secret redaction.
-   Add a clear architecture diagram and document data flow, module
    responsibilities, rule limitations, and threat assumptions.
-   Document installation, configuration, supported formats, rule IDs,
    CLI usage, sample output, and evaluation methodology.
-   Prepare a small demonstration repository with examples that show:
    1.  A straightforward configuration issue
    2.  A multi-resource risk relationship
    3.  An inferred attack path with traceable evidence
    4.  A prioritized remediation plan
    5.  An AI explanation and deterministic fallback, if AI is
        configured
-   Ensure the final report distinguishes implemented functionality from
    future work.

### Deliverables

-   Tested, documented implementation
-   Reproducible demonstration
-   Final technical report and presentation material

### Exit Criteria

A fresh environment can run the documented demonstration and tests, and
the final submission accurately reflects what was implemented and
measured.

## Recommended Build Order

Implement phases in order. The minimum viable version should complete
**Phases 1--3 and 8** first, so the project already has a usable
deterministic scanner and CLI. Then implement **Phases 4--6** for
graph-based reasoning and prioritization, **Phase 7** for optional AI
explanations, and **Phases 9--10** for evaluation and final hardening.

If time is limited, prioritize a smaller set of well-tested rules and a
clearly validated attack-path scenario over a large number of shallow
checks. Support for a file format should be considered complete only
when parsing, rule coverage, and tests exist for it.
