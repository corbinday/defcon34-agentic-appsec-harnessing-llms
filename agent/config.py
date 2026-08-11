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

# The tool layer is a separate process reached over MCP (stdio). One entry per
# server: `script` is relative to the repo root, `tools` is exactly the tool
# names that server exposes, and core/mcp_client.py routes a call to the server
# that claims that name. Adding command injection later is a new entry here plus
# a new server file -- the harness and the two existing tools do not change.
# Two entries claiming the same tool name is an error, not a fallback.
MCP_SERVERS = [
    {"name": "dvwa-sqli-dast",
     "script": "mcp_server.py",
     "tools": ["enumerate_endpoints", "evaluate_sqli"]},
]

# Debug bypass, set by `python agent/pipeline.py --direct`. True imports
# core/browser.py and core/prober.py in process, which also bypasses the
# allow-list and request-budget enforcement that live in the server. Leave it
# False: MCP is the normal transport.
BYPASS_MCP = False

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


# ---------------------------------------------------------------------------
# MCP servers
# ---------------------------------------------------------------------------
# The tool layer reaches the target through MCP, not through a direct import.
# That is the default and there is no flag to turn it on -- --direct exists only
# for debugging, because a stack trace through a subprocess is harder to read.
#
# Why a registry rather than one hardcoded server: the boundary is the point.
# Adding command injection later, or a third-party MCP server for recon, means
# appending an entry here. The harness does not change, the contract does not
# change, and the new tools show up next to the existing two.
#
# Each entry: name, the command to spawn, its arguments, and which tools it is
# expected to expose. The expected list is checked at startup, so a server that
# silently stops exposing a tool fails loudly instead of quietly doing nothing.
MCP_SERVERS = [
    {
        "name": "sqli-dast",
        "script": "mcp_server.py",
        "tools": ["enumerate_endpoints", "evaluate_sqli"],
        "note": "Ours. Owns the session, the allow-list and the request budget.",
    },
    # {
    #     "name": "cmdi-dast",
    #     "script": "mcp_cmdi_server.py",
    #     "tools": ["evaluate_command_injection"],
    #     "note": "Next vulnerability class. Same shape, new skill folder.",
    # },
]

# Debug escape hatch only. Leave this False.
BYPASS_MCP = False
