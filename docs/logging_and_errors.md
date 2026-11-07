# Logging and Error Handling

The project does not configure an application logger. Parsers return errors in `ParseResult.errors` as `Finding` objects with the `PARSER_ERROR` rule ID. Invalid caller arguments may raise `ValueError`. Some parser failures include source line context where available.

There is no directory-wide scanner or orchestration layer to coordinate logging. `structlog` is not a dependency. The parser's safe YAML loading and returned error model do not constitute full validation of input formats.

When orchestration is introduced, logs should avoid recording raw configuration contents and should redact secret values. A structured logging dependency can be considered if the implemented workflow needs one. This document records a future security constraint, not an existing logging configuration.
