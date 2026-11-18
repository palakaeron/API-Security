"""OWASP API Top-10 detection engine.

Each detector module in this package is independently importable and follows
the same contract:

- Accepts a ``base_url`` (validated against the controlled-lab allowlist before
  any network I/O) and a ``TargetPolicy``.
- Returns a ``DetectorResult`` containing zero or more ``Evidence`` objects.
- Declares its OWASP category, severity baseline, confidence, and remediation
  reference in a structured way.
- Never makes raw httpx/requests calls — all outbound I/O goes through
  ``http_client.controlled_get`` / ``controlled_post``, which enforce the
  allowlist check first.

Import order within M4:
  bola → broken_auth → bfla → bopla → misconfiguration → jwt_analyzer
"""
