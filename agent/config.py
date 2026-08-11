"""Every knob in one file. OWNER: Mike (models), shared for the rest.

Model ids live here and nowhere else. When a model turns out not to emit tool
calls reliably, this is the single line that changes.
"""

ORCHESTRATOR_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
SUBAGENT_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

# The allow-list is a safety control, not a convenience. core/session.py raises
# on anything not listed here; no prompt is involved in enforcing it.
ALLOWED_TARGETS = [
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "https://dvwa-production-a515.up.railway.app",
]

DEFAULT_TARGET = "http://localhost:8080"

MAX_REQUESTS = 300
REQUEST_DELAY_SEC = 0.2
HTTP_TIMEOUT_SEC = 20

DVWA_CREDS = {"username": "admin", "password": "password"}

# Triage picks at most this many points to confirm. The cap is the difference
# between our tool and a scanner that fires at everything.
MAX_CANDIDATES = 6
