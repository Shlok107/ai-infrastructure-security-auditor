# Logging and Error Handling Status

The current project does not configure an application logger. Parser failures are returned as `Finding` objects in `ParseResult.errors`; invalid caller arguments may raise `ValueError`. There is no scan orchestration layer, and `structlog` is not currently a dependency.

When a scanner workflow is added, logging should avoid raw configuration contents and redact secret values. A structured logging library can be selected at that point if the implementation needs it. This file records a security constraint for future work, not an implemented logging configuration.
