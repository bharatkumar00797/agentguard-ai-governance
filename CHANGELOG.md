# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-10-10

First stable release.

### Added

- Guard proxy for inputs, tool results, proposed tool calls and model outputs with the verdict
  ladder `allow < redact < require_approval < deny`, findings and 0-100 risk scoring with
  per-policy approval / deny thresholds.
- Detectors with Unicode normalisation: prompt injection (5 families), jailbreaks (4 families)
  and sensitive data (private keys, cloud / GitHub / `sk-` keys, JWTs, passwords, email, cards
  with Luhn check, SSN, PAN, phone) with typed redaction.
- Declarative YAML / JSON policy engine: first-match tool and agent globs, default deny, typed
  argument constraints (enum, range, length, full-match pattern, deny patterns, path prefixes
  with traversal rejection, URL / email domain allowlists), extra-argument control, sliding-window
  rate limits, cost budgets, approval gates and `approval_when` escalation.
- Exfiltration defence: secrets in tool arguments deny the call, injected text escalates it.
- Human approval queue with single resolution, reviewer name and audit entries.
- Hash-chained JSON Lines audit log with optional HMAC key and chain verification.
- Offline mock provider and OpenAI-compatible provider (OpenAI, Groq, Ollama) with retries.
- Guarded agent loop that fences tool results as untrusted data and quarantines injections.
- Packaged policies `default`, `fintech`, `devops` and 5 attack scenarios.
- CLI: `scan`, `check-tool`, `demo`, `scenarios`, `policies --validate`, `audit verify`, `serve`.
- FastAPI service with guard, scan, approvals, audit, policies and scenario endpoints, OpenAPI
  docs, API-key / dev / public-demo access modes, rate limits, 64 KB body cap, strict CSP and
  security headers.
- No-build dashboard: playground, scenario timeline, approvals inbox, audit log with chain status.
- Hardened multi-stage Docker image, docker compose, Render, Fly.io, Railway and Vercel configs,
  end-to-end smoke test script and Docker smoke job in CI.

[Unreleased]: https://github.com/bharatkumar00797/agentguard-ai-governance/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bharatkumar00797/agentguard-ai-governance/releases/tag/v1.0.0
