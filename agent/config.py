"""Every knob in one file. OWNER: Mike (models), shared for the rest.

Model ids live here and nowhere else. When a model turns out not to emit tool
calls reliably, this is the single line that changes.
"""

import os

ORCHESTRATOR_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
SUBAGENT_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

# Bedrock region and sampling. agent/deep_agent.py reads these and nothing else
# -- no model id and no region is written anywhere outside this file. Both region
# variables are honoured so a laptop that is already configured needs no edit
# here: AWS_REGION is what boto3 documents, but the .env handed out with the
# class exercises sets AWS_DEFAULT_REGION. Reading only one of them means a
# machine configured the other way silently falls back to us-east-1 and the
# Bedrock call fails with "model not enabled in this region", which reads like a
# permissions problem and is not one.
BEDROCK_REGION = (os.environ.get("AWS_REGION")
                  or os.environ.get("AWS_DEFAULT_REGION")
                  or "us-east-1")

# Low, not zero: requirement 6 is about the payload set being fixed in code, not
# about the prose being byte-identical. Stage 3 does not involve a model at all.
LLM_TEMPERATURE = 0.2

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
#
# 10, not 6. The crawler now finds 28 points on DVWA, and at 6 the LLM was
# spending two of its slots on guesses -- it argued that `doc` on instructions.php
# "often becomes a database query" and that `step` on the captcha page "often maps
# to a database lookup". Both are wrong, and with only 6 slots a single wrong
# guess pushes a real finding out. The model also reranks between runs, so a tight
# cap turns ordinary rank jitter into a lost vulnerability and a failed
# consistency check.
#
# The cap still does its job: 10 of 28 is 36% of the surface, and at 12 requests
# per point that is 120 against a budget of 300.
MAX_CANDIDATES = 10
