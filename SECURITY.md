# Security Policy

AgentGuard is a security and governance layer for AI agents, so bypasses of its controls are
treated as vulnerabilities. The design is described in the
[security model](README.md#security-model) section of the README.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | yes |
| < 1.0 | no |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- Use GitHub's private vulnerability reporting:
  **Security → Report a vulnerability** on
  <https://github.com/bharatkumar00797/agentguard-ai-governance/security>.
- Include the affected version or commit, a description of the impact, and steps or a proof of
  concept to reproduce it.

You can expect an acknowledgement within 3 working days and a status update within 10 working
days. Once a fix is released we are happy to credit you in the changelog unless you prefer to
stay anonymous.

## Scope

In scope:

- A tool call that a policy should deny or hold for approval but is allowed (argument
  constraint, domain / path allowlist, rate limit or budget bypass, rule-matching errors).
- Secrets leaving through tool arguments or outputs despite the policy's text switches.
- Resolving an approval twice, as another caller, or without an audit entry.
- Audit records that can be edited, removed or reordered without `audit verify` failing, or
  raw prompt / argument text written to the log.
- Authentication or authorization bypass in the REST API, inline custom policies or a real
  provider in public-demo mode.
- Bypassing rate limits or the request body cap; XSS or CSP bypass in the dashboard.
- Secrets exposed in API responses, logs or the published Docker image.

Out of scope:

- Injection or jailbreak phrasings the heuristic detectors do not flag, **unless** they lead to
  a tool call or data flow that the policy should have stopped.
- Rebuilding the whole audit chain with write access when `AGENTGUARD_AUDIT_KEY` is unset.
- Shared public-demo identity when `AGENTGUARD_TRUST_PROXY` is unset behind a reverse proxy.
- In-memory state loss across restarts or serverless instances (documented caveat).
- Vulnerabilities in third-party platforms or dependencies without a demonstrated impact on
  AgentGuard.
