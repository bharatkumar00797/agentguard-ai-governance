"""Serverless entrypoint (Vercel): exposes the AgentGuard FastAPI app as ``app``.

Every guard endpoint is a short synchronous request, so the service runs unchanged on
serverless hosts. Unless API keys are configured the deployment is a public demo: packaged
policies and scenarios with the offline mock provider. Approvals and the audit chain live in
memory per function instance; scenario runs return their full step timeline in the response.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.is_dir() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentguard.api import create_app  # noqa: E402  (path setup must run first)

app = create_app()
