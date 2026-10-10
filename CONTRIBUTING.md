# Contributing to AgentGuard

Thanks for your interest in improving AgentGuard. Bug reports, new detector patterns, policy
examples, documentation fixes and pull requests are all welcome.

## Development setup

Requirements: Python 3.11 to 3.13, `git`. Docker is optional (only for the container checks).

```bash
git clone https://github.com/bharatkumar00797/agentguard-ai-governance.git
cd agentguard-ai-governance
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Everything runs offline with the default `mock` provider, so no API key is needed for
development or tests. To try a real model, copy `.env.example` to `.env` and set
`AGENTGUARD_PROVIDER` / `AGENTGUARD_BASE_URL` / `AGENTGUARD_API_KEY` / `AGENTGUARD_MODEL`.
Never commit `.env` or any key.

## Checks

Run these before opening a pull request; CI runs the same commands on Python 3.11, 3.12 and 3.13.

```bash
ruff check .            # lint
ruff format .           # format (CI uses: ruff format --check .)
mypy                    # strict type checking of src/agentguard
pytest                  # full test suite, offline
```

Optional end-to-end checks:

```bash
agentguard demo all --audit audit.jsonl && agentguard audit verify audit.jsonl
agentguard serve --dev                               # dashboard on http://127.0.0.1:8000
python scripts/smoke_test.py http://127.0.0.1:8000   # guard, approvals, scenarios, audit chain
docker compose up --build --wait                     # hardened container
```

## Guidelines

- Keep the mock provider the default: every feature must work without network access or keys.
- New code is fully typed (`mypy --strict` must pass) and comes with tests.
- Security decisions stay deterministic: the guard never asks a model whether something is safe.
- Prefer allowlists (domains, prefixes, enums, full-match patterns) over new blocklist regexes.
- New detector patterns go in `detectors.py` with a positive **and** a false-positive test.
- The audit log stores verdicts and codes only; never add raw prompts, arguments or outputs.
- Anything touching auth, access modes, rate limiting or the body cap needs a test proving the
  control holds (see `tests/test_api.py`).
- Adding a scenario: add `src/agentguard/scenarios/<id>.yaml` with an `expect` block and extend
  `scripts/smoke_test.py`.

## Commit style

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(policy): support agent globs on tool rules
fix(detectors): catch zero-width split injections
docs: document approval_when escalation
test: cover audit chain reordering
ci: smoke-test the Docker image
```

Keep commits small and focused, write the subject in the imperative mood, and update
`CHANGELOG.md` under **Unreleased** for user-visible changes.

## Reporting security issues

Please do not open public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).
