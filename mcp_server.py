"""The MCP server the team diagram promised: exactly two tools, over stdio.

    harness (agent/pipeline.py)
        |  stdio, JSON-RPC
        v
    mcp_server.py            <- owns the Session, the allow-list, the budget
        |  plain python calls
        v
    core/browser.py  core/prober.py  ->  DVWA

WHY THIS EXISTS AND NOT JUST agent/deep_agent.py
------------------------------------------------
The BaseTool wrappers in agent/deep_agent.py run *inside* the harness process.
Anything the harness does -- a model that talks it into a new URL, a stage that
builds its own requests.Session -- happens on the same side of the fence as the
safety controls, so the controls are only as good as the harness. Moving the two
functions behind a process boundary makes that impossible by construction:

  * The allow-list (agent/config.ALLOWED_TARGETS, enforced by core/session.py
    and again by core/browser.py) lives in THIS process. A tool call naming a
    host that is not on the list raises here and never reaches the network.
  * The request budget (config.MAX_REQUESTS) is counted by the one Session in
    THIS process. The harness cannot reset it, cannot bypass it, and cannot
    open a second one, because it has no handle on it -- there is no `session`
    argument anywhere in the wire protocol.
  * The login happens once, at server startup. AGENTS.md section 2: a login per
    parameter burns a login per payload and DVWA hands out a fresh user_token
    on every render. The harness cannot make that mistake because it cannot
    ask for a login at all.
  * Credentials never cross the wire. They come from the environment
    (DAST_USERNAME / DAST_PASSWORD) or from agent/config.DVWA_CREDS.

So the contract's `session` and `auth` are deliberately NOT tool arguments.
Everything else in AGENTS.md section 2 is on the wire verbatim, including the
optional `dbms` and `depth` hints on evaluate_sqli.

WHY print() IS REDIRECTED TO stderr
-----------------------------------
stdout IS the transport. core/browser.py prints crawl progress and core/*
prints diagnostics; a single stray line on fd 1 corrupts the JSON-RPC stream
and the client dies with a parse error that looks nothing like its cause.
main() swaps sys.stdout for a shim whose .write() goes to stderr while its
.buffer stays the real stdout that mcp.server.stdio wraps. Diagnostics stay
visible (the client forwards our stderr), the protocol stays clean.

Run it:
    DAST_TARGET=https://dvwa-production-a515.up.railway.app python mcp_server.py
    python mcp_server.py --target https://dvwa-production-a515.up.railway.app

Normally you do not run it by hand -- core/mcp_client.py spawns it, and
`python agent/pipeline.py --target URL` drives the whole chain through it.
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Dict, Optional

REPO_ROOT = Path(__file__).resolve().parent
# Same bootstrap as agent/pipeline.py: the server is spawned as a script, so the
# repo root has to be on sys.path before the package imports below.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent import config  # noqa: E402
from core.browser import enumerate_endpoints as _crawl  # noqa: E402
from core.prober import evaluate_sqli as _probe  # noqa: E402
from core.session import Session  # noqa: E402

SERVER_NAME = "dvwa-sqli-dast"

# The one session for the whole server process. Created and logged in once by
# start_session(); every tool call borrows it and nothing else may replace it.
_SESSION = None
_TARGET = None

# core/prober.py may or may not have grown the dbms/depth arguments yet. We do
# not guess: we look, and if a caller asks for something this build cannot do we
# say so in the contract's `error` field instead of silently ignoring the hint.
_PROBE_PARAMS = set(inspect.signature(_probe).parameters)


class ServerNotStarted(RuntimeError):
    """A tool was called before start_session() logged in. Never silent."""


def _env_target():
    return os.environ.get("DAST_TARGET") or config.DEFAULT_TARGET


def _env_int(name, default):
    raw = os.environ.get(name)
    if not raw:
        return default
    return int(raw)


def _creds():
    creds = dict(config.DVWA_CREDS)
    if os.environ.get("DAST_USERNAME"):
        creds["username"] = os.environ["DAST_USERNAME"]
    if os.environ.get("DAST_PASSWORD"):
        creds["password"] = os.environ["DAST_PASSWORD"]
    return creds


def start_session(target=None, max_requests=None):
    """Build the one Session and log in once. Raises loudly if it cannot.

    A server that came up without a login would answer every tool call with a
    crawl of the login page and report the application as having no parameters,
    which is a lie that survives three more stages.
    """
    global _SESSION, _TARGET
    _TARGET = (target or _env_target()).rstrip("/")
    budget = max_requests or _env_int("DAST_MAX_REQUESTS", config.MAX_REQUESTS)

    session = Session(_TARGET, config.ALLOWED_TARGETS,
                      max_requests=budget,
                      delay=config.REQUEST_DELAY_SEC,
                      timeout=config.HTTP_TIMEOUT_SEC)
    creds = _creds()
    if not session.login(**creds):
        raise SystemExit(
            "[mcp-server] login to %s as %r failed. Check the target, the "
            "credentials (DAST_USERNAME / DAST_PASSWORD or agent/config.py) "
            "and that the host is in ALLOWED_TARGETS."
            % (_TARGET, creds["username"]))
    _SESSION = session
    print("[mcp-server] target %s, logged in as %s, budget %d requests, "
          "allow-list %s" % (_TARGET, creds["username"], budget,
                             config.ALLOWED_TARGETS))
    return session


def _session():
    if _SESSION is None:
        raise ServerNotStarted(
            "no Session: start_session() was never called. Start the server "
            "through main() (python mcp_server.py) so the login happens once, "
            "at startup.")
    return _SESSION


def _unsupported(name, value):
    """The contract dict for 'this build cannot honour that hint'.

    AGENTS.md section 2: `error` is not politeness. A parameter we did not
    actually test the way the caller asked is undetermined, not clean.
    """
    return {"confirmed": False, "technique": "none", "evidence": "",
            "payload": "", "stage_reached": 0, "requests_used": 0,
            "error": "core/prober.py in this checkout does not accept %r "
                     "(it takes %s), so %s=%r could not be honoured. Nothing "
                     "was sent. Re-run with the default, or wire the argument "
                     "through to skills/sqli-payloads/scripts/payloads.py "
                     "select(), which already supports it."
                     % (name, sorted(_PROBE_PARAMS), name, value)}


# ---------------------------------------------------------------------------
# The two functions. Bodies only -- the MCP plumbing is in build_server().
# ---------------------------------------------------------------------------
def call_enumerate_endpoints(url):
    """core/browser.py, with the server's session. No logic duplicated here."""
    return _crawl(url, session=_session())


def call_evaluate_sqli(url, method, param, context, value="", siblings=None,
                       dbms="unknown", depth="standard"):
    """core/prober.py, with the server's session. No logic duplicated here."""
    extra = {}
    for name, given, default in (("dbms", dbms, "unknown"),
                                 ("depth", depth, "standard")):
        if name in _PROBE_PARAMS:
            extra[name] = given
        elif given != default:
            return _unsupported(name, given)
    return _probe(url, method, param, context, value=value, siblings=siblings,
                  session=_session(), **extra)


# ---------------------------------------------------------------------------
# MCP plumbing
# ---------------------------------------------------------------------------
def build_server():
    """Register exactly two tools on a FastMCP server and return it.

    The mcp import is in here, not at module scope, so `import mcp_server`
    still works on a checkout where the package is missing -- and says what to
    install rather than dying on an ImportError traceback.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise SystemExit(
            "the 'mcp' package is not installed in this environment.\n"
            "    pip install mcp\n"
            "Without it the pipeline still runs: pass --direct and stages 1 and 3 "
            "call core/browser.py and core/prober.py in process.\n"
            "Original import error: %s" % exc)

    import anyio

    server = FastMCP(SERVER_NAME)

    @server.tool(name="enumerate_endpoints")
    async def enumerate_endpoints_tool(url: str) -> str:
        """Crawls the target web application with a real browser and returns
        EVERY request parameter it accepts, as a JSON list with one row per
        parameter: url (full URL including scheme and host), method (GET or
        POST), param (exactly one parameter name, never a list), value (the
        original value the crawler saw, which is what tells you whether the
        parameter looks numeric or string), siblings (every OTHER field of the
        same form at its original value, which must be replayed on every
        request or the server-side guard never runs the query), and
        requires_auth (true when the crawler was bounced to a login page
        instead of reaching the form, which means UNDETERMINED and not clean).
        This tool ONLY looks: it sends no payloads, it tests nothing, and it
        never reports a vulnerability. Call it once at the start of an
        assessment to obtain the attack surface and then rank the rows it
        returned; do not guess parameter names, and do not call it twice for
        the same target because the crawl is deterministic and the second
        result is identical to the first. Authentication is not your problem
        and is not an argument here: this server logged into the target once at
        startup with credentials it holds itself, and it enforces the target
        allow-list and the request budget on every call, so a URL outside the
        allow-list is refused here rather than crawled.
        """
        return json.dumps(
            await anyio.to_thread.run_sync(call_enumerate_endpoints, url),
            ensure_ascii=False)

    @server.tool(name="evaluate_sqli")
    async def evaluate_sqli_tool(url: str, method: str, param: str,
                                 context: str, value: str = "",
                                 siblings: Optional[Dict[str, str]] = None,
                                 dbms: str = "unknown",
                                 depth: str = "standard") -> str:
        """Fires a FIXED, code-owned SQL injection payload group at ONE
        parameter of ONE endpoint and returns the evidence it observed, as
        JSON. THIS TOOL DECIDES THE VERDICT AND YOU DO NOT: the boolean in
        'confirmed' is the only thing in this system allowed to call a
        parameter vulnerable, and reading a response yourself and concluding
        that something looks injectable is not evidence. You choose three
        labels and nothing else -- context ("numeric", "string",
        "double-quoted", "paren" or "unknown", your reading of what the
        original value looks like), dbms ("mysql", "postgres", "mssql",
        "oracle", "sqlite" or "unknown", a hint and not a promise) and depth
        ("quick" for stage 1 only, "standard" for stages 1-2, "deep" for all
        three dialect sweeps, which is slow and needs justifying in the
        report) -- and the code expands those labels into an exact ordered
        payload list, so the same labels always produce the same requests. It
        walks the techniques in order and stops at the first confirmation:
        error-based (a known database error signature appears in the body),
        boolean-blind (a TRUE payload matches the baseline while a FALSE
        payload does not), then time-blind (at least four seconds slower than
        baseline, reproduced twice). Pass `value` and `siblings` exactly as
        enumerate_endpoints returned them: payloads are APPENDED to value, so
        id=1 is probed as id=1' and never as id=', and dropping siblings is a
        guaranteed false negative because the application only runs its query
        when the whole form arrives. It returns confirmed (bool), technique,
        evidence (the verbatim observation, never a summary), payload (the
        exact string that worked), stage_reached, requests_used and error; a
        non-null error means the attempt could not run at all, which makes
        that point UNDETERMINED rather than safe and it must be reported as
        not tested. Call it once per parameter that is worth spending requests
        on, never on the whole attack surface.
        """
        result = await anyio.to_thread.run_sync(
            call_evaluate_sqli, url, method, param, context, value, siblings,
            dbms, depth)
        return json.dumps(result, ensure_ascii=False)

    return server


class _StdoutShim:
    """print() goes to stderr; .buffer stays the real stdout for the transport.

    mcp.server.stdio re-wraps sys.stdout.buffer to guarantee UTF-8, so the
    protocol keeps the real file descriptor while every print() in core/ is
    diverted to stderr, where the client forwards it to the operator.
    """

    def __init__(self, real_stdout, err):
        self.buffer = real_stdout.buffer
        self._err = err

    def write(self, text):
        return self._err.write(text)

    def flush(self):
        return self._err.flush()

    def writable(self):
        return True

    def isatty(self):
        return False

    def fileno(self):
        return self._err.fileno()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="MCP server exposing enumerate_endpoints and evaluate_sqli "
                    "over stdio. The session, the login, the allow-list and "
                    "the request budget live here, not in the caller.")
    ap.add_argument("--target", default=None,
                    help="target base URL. Defaults to $DAST_TARGET, then to "
                         "agent/config.py DEFAULT_TARGET. Must be in "
                         "ALLOWED_TARGETS or every call raises.")
    ap.add_argument("--max-requests", type=int, default=None,
                    help="request budget for this server's session. Defaults "
                         "to $DAST_MAX_REQUESTS, then to config.MAX_REQUESTS.")
    args = ap.parse_args(argv)

    sys.stdout = _StdoutShim(sys.stdout, sys.stderr)
    start_session(args.target, args.max_requests)
    server = build_server()
    print("[mcp-server] serving 2 tools over stdio: enumerate_endpoints, "
          "evaluate_sqli")
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
