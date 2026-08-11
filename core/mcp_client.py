"""Synchronous client for mcp_server.py. Same two names, same signatures.

The point of this module is that agent/pipeline.py should not have to care
which side of a process boundary the tools live on:

    from core.browser import enumerate_endpoints      # in process
    from core.prober  import evaluate_sqli

    from core.mcp_client import enumerate_endpoints   # over MCP stdio
    from core.mcp_client import evaluate_sqli

Both pairs take the same arguments and return the same python objects. The MCP
pair is the normal transport; the in-process pair is what --direct falls back
to for debugging. The only argument that is deliberately missing is `session`:
the server owns the one session, and that is the whole reason the server exists
(see mcp_server.py).

Which servers get started, and which tool names each one serves, is
config.MCP_SERVERS. A second server (command injection, recon) is an entry
there plus a new server file; connect() routes each tool name to the server
that claims it and refuses two servers claiming the same name.

ONE CONNECTION, REUSED
----------------------
The MCP client API is async and every transport is a context manager, so the
obvious implementation -- asyncio.run() per call -- would spawn a server, log
in, run one tool and tear it all down again, once per parameter. Against a
shared remote DVWA that is a login per payload, which AGENTS.md section 2 says
melts the target. Instead each server gets one background thread running one
event loop that holds its stdio connection open, and the two sync functions
below hand coroutines to it. connect() is idempotent; close() (also registered
with atexit) shuts the subprocesses down.

FAILURES ARE RAISED
-------------------
A tool call that errors, a response that is not JSON, a server that died: all
raise. None of them return an empty list or a plausible-looking dict, because
an empty stage 1 reads downstream as "this application has no parameters" and
an invented stage 3 verdict reads as "not vulnerable".

Verify without the pipeline:
    python core/mcp_client.py --target https://dvwa-production-a515.up.railway.app
"""

from __future__ import annotations

import asyncio
import atexit
import json
import os
import sys
import threading
from datetime import timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_SCRIPT = REPO_ROOT / "mcp_server.py"

# The crawl walks up to 40 pages with a browser and one time-blind probe costs
# five seconds a payload, so the read timeout is generous. It is not absent:
# a hung server has to surface as an error, not as a pipeline that never ends.
ENUMERATE_TIMEOUT_SEC = 900
EVALUATE_TIMEOUT_SEC = 900
# Startup includes launching python and logging into the target.
CONNECT_TIMEOUT_SEC = 120


class McpUnavailable(RuntimeError):
    """The mcp package is not installed here. Says what to install."""


class McpCallFailed(RuntimeError):
    """The server reported an error, or answered something we cannot parse."""


def _import_mcp():
    """Imported late on purpose: a checkout without `mcp` must still be able to
    `import core.mcp_client`, and must be told what to install rather than
    dying on a bare ImportError three frames deep."""
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import get_default_environment, stdio_client
    except ImportError as exc:
        raise McpUnavailable(
            "the 'mcp' package is not installed in this environment.\n"
            "    pip install mcp\n"
            "Without it, run the pipeline with --direct: stages 1 and 3 then "
            "call core/browser.py and core/prober.py in process, which is the "
            "default and needs nothing extra.\n"
            "Original import error: %s" % exc)
    return ClientSession, StdioServerParameters, stdio_client, get_default_environment


class _Connection:
    """One stdio server subprocess plus the loop thread that talks to it."""

    def __init__(self, target, max_requests=None, server_script=None):
        self.target = target
        self.max_requests = max_requests
        self.server_script = Path(server_script or SERVER_SCRIPT)
        self._loop = None
        self._thread = None
        self._session = None
        self._stop = None
        self._ready = threading.Event()
        self._error = None

    # -- lifecycle ---------------------------------------------------------
    def open(self):
        if not self.server_script.is_file():
            raise McpCallFailed("no MCP server at %s" % self.server_script)
        _import_mcp()          # fail here, with the pip line, not in the thread

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True,
                                        name="mcp-client-loop")
        self._thread.start()
        if not self._ready.wait(CONNECT_TIMEOUT_SEC):
            raise McpCallFailed(
                "MCP server at %s did not finish starting within %ds. It logs "
                "into the target at startup, so check that the target is up "
                "and in ALLOWED_TARGETS." % (self.server_script, CONNECT_TIMEOUT_SEC))
        if self._error is not None:
            raise McpCallFailed(
                "MCP server failed to start: %s: %s"
                % (type(self._error).__name__, self._error))
        return self

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        finally:
            self._loop.close()

    async def _serve(self):
        (ClientSession, StdioServerParameters, stdio_client,
         get_default_environment) = _import_mcp()

        env = dict(get_default_environment())
        env.update(os.environ)
        env["DAST_TARGET"] = self.target
        # Writing artifacts on a Windows console dies on cp949 otherwise, and
        # the server's diagnostics come back to us on stderr.
        env["PYTHONIOENCODING"] = "utf-8"
        if self.max_requests:
            env["DAST_MAX_REQUESTS"] = str(self.max_requests)

        params = StdioServerParameters(
            command=sys.executable,
            args=[str(self.server_script), "--target", self.target],
            env=env,
            cwd=str(REPO_ROOT),
        )

        self._stop = asyncio.Event()
        try:
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self._session = session
                    self._ready.set()
                    await self._stop.wait()
        except BaseException as exc:          # noqa: BLE001 - reported, never hidden
            self._error = exc
            self._session = None
            self._ready.set()

    def close(self):
        if self._loop is not None and self._stop is not None and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread is not None:
            self._thread.join(timeout=30)
        self._session = None

    # -- calling -----------------------------------------------------------
    def call(self, name, arguments, timeout_sec):
        if self._session is None:
            raise McpCallFailed(
                "MCP connection is not open (server error: %s)" % (self._error,))
        future = asyncio.run_coroutine_threadsafe(
            self._session.call_tool(
                name, arguments,
                read_timeout_seconds=timedelta(seconds=timeout_sec)),
            self._loop)
        result = future.result(timeout=timeout_sec + 30)
        return _payload(name, result)


def _payload(name, result):
    """Pull the JSON document out of a CallToolResult. Raises on anything else."""
    text_parts = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text is not None:
            text_parts.append(text)
    text = "\n".join(text_parts).strip()

    if getattr(result, "isError", False):
        raise McpCallFailed(
            "MCP tool %s reported an error: %s" % (name, text or "(no detail)"))
    if not text:
        raise McpCallFailed(
            "MCP tool %s returned no text content: %r" % (name, result))
    try:
        return json.loads(text)
    except ValueError as exc:
        raise McpCallFailed(
            "MCP tool %s returned content that is not JSON (%s). First 300 "
            "characters: %s" % (name, exc, text[:300]))


# ---------------------------------------------------------------------------
# Module-level connections, opened once and reused. One per entry in
# config.MCP_SERVERS; calls are routed to the server that claims the tool name.
# ---------------------------------------------------------------------------
_CONNS = {}          # server name -> _Connection
_ROUTES = {}         # tool name   -> _Connection
_LOCK = threading.RLock()


def _default_servers():
    # Late import: core/ must not need agent/ to be importable.
    from agent import config
    return config.MCP_SERVERS


def connect(target, max_requests=None, servers=None):
    """Start every server in the registry and route its tool names to it.

    Idempotent. Reconnecting to a different target is a caller bug, not
    something to paper over: the server logged into the first target at startup
    and its session is bound to it.
    """
    if servers is None:
        servers = _default_servers()
    if not servers:
        raise McpCallFailed(
            "config.MCP_SERVERS is empty, so there is no tool layer to call.")

    with _LOCK:
        for entry in servers:
            name = entry["name"]
            existing = _CONNS.get(name)
            if existing is not None:
                if existing.target != target:
                    raise McpCallFailed(
                        "MCP server %r is already connected to %s; close() "
                        "before connecting to %s"
                        % (name, existing.target, target))
                continue
            conn = _Connection(target, max_requests,
                               REPO_ROOT / entry["script"]).open()
            _CONNS[name] = conn
            for tool in entry["tools"]:
                clash = _ROUTES.get(tool)
                if clash is not None and clash is not conn:
                    raise McpCallFailed(
                        "two MCP servers both claim the tool name %r. One name "
                        "each, no aliases (AGENTS.md section 2) -- fix "
                        "config.MCP_SERVERS." % tool)
                _ROUTES[tool] = conn
    return _CONNS


def close():
    """Shut every server subprocess down. Safe to call twice."""
    with _LOCK:
        conns = list(_CONNS.values())
        _CONNS.clear()
        _ROUTES.clear()
    for conn in conns:
        conn.close()


atexit.register(close)


def _route(tool):
    conn = _ROUTES.get(tool)
    if conn is not None:
        return conn
    raise McpCallFailed(
        "no MCP server is serving %r. Call core.mcp_client.connect(target) "
        "once at startup (agent/pipeline.py does this unless you passed "
        "--direct), and check that a config.MCP_SERVERS entry lists that tool "
        "name. Connected servers: %s" % (tool, sorted(_CONNS) or "none"))


# ---------------------------------------------------------------------------
# The two functions. Same names and same signatures as core/browser.py and
# core/prober.py, so swapping the import is the whole integration.
# ---------------------------------------------------------------------------
def enumerate_endpoints(url, auth=None):
    """Crawl over MCP. Returns the contract rows, exactly as core/browser.py."""
    if auth:
        raise McpCallFailed(
            "credentials do not cross the MCP boundary. The server logs in "
            "once at startup; set DAST_USERNAME / DAST_PASSWORD in its "
            "environment, or edit agent/config.py DVWA_CREDS.")
    rows = _route("enumerate_endpoints").call(
        "enumerate_endpoints", {"url": url}, ENUMERATE_TIMEOUT_SEC)
    if not isinstance(rows, list):
        raise McpCallFailed(
            "enumerate_endpoints returned %s, expected a list of rows"
            % type(rows).__name__)
    return rows


def evaluate_sqli(url, method, param, context, value="", siblings=None,
                  dbms="unknown", depth="standard"):
    """Probe one parameter over MCP. Returns the contract dict verbatim."""
    result = _route("evaluate_sqli").call(
        "evaluate_sqli",
        {"url": url, "method": method, "param": param, "context": context,
         "value": value, "siblings": siblings, "dbms": dbms, "depth": depth},
        EVALUATE_TIMEOUT_SEC)
    if not isinstance(result, dict) or "confirmed" not in result:
        raise McpCallFailed(
            "evaluate_sqli returned %r, expected the contract dict with a "
            "'confirmed' key" % (result,))
    return result


if __name__ == "__main__":
    import argparse

    sys.path.insert(0, str(REPO_ROOT))
    from agent import config

    ap = argparse.ArgumentParser(
        description="Round-trip one enumerate_endpoints call through the MCP "
                    "server, then one evaluate_sqli call on the first row that "
                    "looks worth probing.")
    ap.add_argument("--target", default=config.DEFAULT_TARGET)
    ap.add_argument("--probe", action="store_true",
                    help="also fire evaluate_sqli at /vulnerabilities/sqli/ id")
    a = ap.parse_args()

    connect(a.target)
    try:
        points = enumerate_endpoints(a.target)
        print("enumerate_endpoints -> %d rows" % len(points))
        for row in points[:5]:
            print("  %s %s param=%s value=%r siblings=%s"
                  % (row["method"], row["url"], row["param"], row["value"],
                     sorted(row["siblings"])))
        if a.probe:
            hit = next((p for p in points
                        if p["param"] == "id" and "sqli" in p["url"]), None)
            if hit is None:
                raise SystemExit("no id parameter on a sqli page in the crawl")
            print("evaluate_sqli -> %s"
                  % evaluate_sqli(hit["url"], hit["method"], hit["param"],
                                  "numeric", value=hit["value"],
                                  siblings=hit["siblings"]))
    finally:
        close()
