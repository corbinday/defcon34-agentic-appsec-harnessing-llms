"""The LLM half of the chain: stage 2 (triage) and stage 4 (report). OWNER: Mike.

This is the deep-agent implementation of the two stages that agent/pipeline.py
currently fills with deterministic Python. Nothing here is imported unless the
pipeline is started with --llm, and nothing here imports deepagents, langchain
or boto3 at module level -- see "Why the imports are inside functions" below.

    stage 2  llm_triage(points, target, session)  -> ranked subset + context
    stage 4  llm_report(verdicts, target, session) -> writes 05 + 02 artifacts

Both return exactly what the stubs in pipeline.py return, so the two paths are
interchangeable and the stubs stay as the offline fallback.

-----------------------------------------------------------------------------
MIKE: WHAT YOU MUST VERIFY OR FINISH BEFORE THE DEMO
-----------------------------------------------------------------------------
This file has never executed. deepagents, langchain-aws and AWS credentials are
all absent from the machine it was written on, so everything below is written
against examples/deepagent_sast_demo.py and
examples/agentic_dast_xss_playwright.py, which are the only authoritative
sources we have for the API. Work down this list:

 1. INSTALL AND CREDENTIALS. `pip install -r requirements.txt`, then export AWS
    credentials (AWS_PROFILE, or AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY).
    Region and model ids come from agent/config.py only -- BEDROCK_REGION was
    added there for this file. Nothing is hardcoded here. Note that
    requirements.txt lists langchain-core but not the `langchain` umbrella
    package that the lecture example imports BaseTool from; _base_tool() tries
    both, so either install works.
 2. ChatBedrockConverse(region_name=...). The lecture examples never pass a
    region because they rely on a .env / AWS_REGION. We pass
    config.BEDROCK_REGION explicitly. If your langchain-aws version names that
    argument differently, fix _chat_model() -- one line.
 3. create_deep_agent() ARGUMENT MIX. deepagent_sast_demo.py passes
    model/tools/backend/system_prompt/skills; agentic_dast_xss_playwright.py
    passes model/tools/subagents/system_prompt. _stage_agent() below passes the
    first set. build_orchestrator() passes both sets at once, and that
    combination is the one thing in this file that no example demonstrates. If
    it raises TypeError, drop `backend`/`skills` from the orchestrator only --
    llm_triage and llm_report do not go through it.
 4. FilesystemBackend(root_dir=REPO_ROOT). AGENTS.md section 7 warns that
    root_dir must contain skills/ or skill loading dies with a ValueError. We
    point it at the repo root, which does. Confirm on the first run.
 5. THE THREAT MODEL IS NOT ITS OWN LLM CALL YET. AGENTS.md says
    artifacts/02_threat_model.md should be a separate call over the same
    evidence. llm_report() currently writes it from the model's SUMMARY plus
    the confirmed verdicts, structurally identical to the stub. If there is
    time, add a third prompt; if there is not, the artifact still exists and is
    still evidence-backed.
 6. THE TWO TOOLS ARE ONLY REACHED THROUGH build_orchestrator(). llm_triage
    hands the crawler output to the model in the prompt instead of making it
    call enumerate_endpoints, so stage 2 costs one LLM turn and cannot loop.
    That is deliberate. Requirement 4 ("custom tool >= 1") is satisfied by the
    BaseTool wrappers being real and wired; if a grader wants to watch a tool
    call happen live, demo build_orchestrator().
 7. TOOL CLASSES LIVE INSIDE _load_tool_classes(). They subclass
    langchain.tools.BaseTool, which cannot be imported at module scope here
    (see below), so `from agent.deep_agent import ConfirmSqliTool` will not
    work. Use build_tools(session).
 8. If the model refuses to emit the labels, the failure is loud: ParseFailure
    with a snippet of what it actually said. Do NOT make it fall back to the
    stub silently -- a run that quietly stopped using the LLM is worse than a
    run that stopped.

Why the imports are inside functions
    deepagents / langchain / langchain-aws are not installed on every laptop on
    this team, and faiss is not installed anywhere. A module-level import would
    make `python agent/pipeline.py` (the no-LLM path, which works today) die on
    import. Every third-party import in this file therefore sits inside the
    function that needs it and raises MissingDependency with the pip line.

Why there is no json.loads() of a model response
    AGENTS.md section 6. Model output is scraped with label regexes; a response
    that does not carry the labels is a ParseFailure, never an empty result.

Why the parsers throw model output away
    A model that returns a URL we never crawled has invented it. _match_point()
    drops any triage block whose (url, method, param) is not in the crawler's
    list, and value/siblings are always re-attached from the crawler row, never
    from the model. Dropping siblings is a guaranteed false negative on DVWA
    (AGENTS.md section 2), so they are not something we let a model retype.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlparse

# Same bootstrap as agent/pipeline.py: `python agent/deep_agent.py` puts agent/
# on sys.path instead of the repo root, and the package imports below would
# fail without this. Importing it as agent.deep_agent is unaffected.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import config  # noqa: E402
from agent import prompts  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = REPO_ROOT / "artifacts"
SKILLS_DIR = REPO_ROOT / "skills"


class MissingDependency(RuntimeError):
    """The agent stack is not installed here. Tells the operator what to run."""


class ParseFailure(RuntimeError):
    """The model answered, but not in the format we parse. Never silent."""


class EmptyResponse(RuntimeError):
    """The agent returned no assistant text at all."""


def _need(what, exc):
    return MissingDependency(
        "%s is not installed in this environment.\n"
        "    pip install -r requirements.txt\n"
        "then provide AWS credentials (AWS_PROFILE, or AWS_ACCESS_KEY_ID and\n"
        "AWS_SECRET_ACCESS_KEY) and check BEDROCK_REGION in agent/config.py.\n"
        "Original import error: %s" % (what, exc))


# ---------------------------------------------------------------------------
# Model and agent construction
# ---------------------------------------------------------------------------
def _base_tool():
    """langchain.tools.BaseTool, the class the lecture example subclasses.

    requirements.txt pins langchain-core but not the langchain umbrella package,
    and the two export the same class, so try the example's import path first
    and fall back to the one we are certain is installed.
    """
    try:
        from langchain.tools import BaseTool
    except ImportError:
        try:
            from langchain_core.tools import BaseTool
        except ImportError as exc:
            raise _need("langchain (BaseTool)", exc)
    return BaseTool


def preflight():
    """Import every third-party dependency the LLM path needs, and nothing else.

    Called by the pipeline before stage 1, so a missing library is discovered
    while the request budget is still untouched instead of after stage 3 spent
    it. Raises MissingDependency; makes no network call and no AWS call.
    """
    try:
        import deepagents                                  # noqa: F401
        from deepagents.backends import FilesystemBackend  # noqa: F401
        from langchain_aws import ChatBedrockConverse      # noqa: F401
    except ImportError as exc:
        raise _need("the agent stack (deepagents / langchain-aws)", exc)
    _base_tool()


def _load_dotenv():
    """Optional convenience, exactly as the lecture examples do it."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return          # a missing .env loader is not a failure worth raising
    load_dotenv()


def _chat_model(model_id):
    """One Bedrock chat model. Model id and region come from agent/config.py."""
    try:
        from langchain_aws import ChatBedrockConverse
    except ImportError as exc:
        raise _need("langchain-aws", exc)
    _load_dotenv()
    return ChatBedrockConverse(model_id=model_id,
                               region_name=config.BEDROCK_REGION,
                               temperature=config.LLM_TEMPERATURE)


def _backend():
    """FilesystemBackend rooted at the repo, so skills/ is inside root_dir."""
    try:
        from deepagents.backends import FilesystemBackend
    except ImportError as exc:
        raise _need("deepagents", exc)
    return FilesystemBackend(root_dir=str(REPO_ROOT), virtual_mode=False)


def _stage_agent(system_prompt, tools, model_id):
    """One deep agent for one stage. Same call shape as the SAST example."""
    try:
        from deepagents import create_deep_agent
    except ImportError as exc:
        raise _need("deepagents", exc)
    return create_deep_agent(
        model=_chat_model(model_id),
        tools=tools,
        backend=_backend(),
        system_prompt=system_prompt,
        skills=[str(SKILLS_DIR)],
    )


# ---------------------------------------------------------------------------
# The two custom tools (requirement 4)
# ---------------------------------------------------------------------------
_TOOL_CLASSES = None


def _load_tool_classes():
    """Define the BaseTool wrappers. Cached, because BaseTool is a pydantic
    model and redefining it per call is pure waste.

    Both tools carry the ONE core.session.Session the run created at startup.
    Neither logs in, and neither is allowed to invent a session of its own:
    a login per parameter is what locks the DVWA account (AGENTS.md section 2).
    """
    global _TOOL_CLASSES
    if _TOOL_CLASSES is not None:
        return _TOOL_CLASSES

    from typing import Any, Dict, Optional, Type

    BaseTool = _base_tool()
    try:
        from pydantic import BaseModel, Field
    except ImportError as exc:
        raise _need("pydantic", exc)

    from core.browser import enumerate_endpoints
    from core.prober import evaluate_sqli

    class CollectInjectionPointsInput(BaseModel):
        url: str = Field(
            description="Base URL of the target application, including scheme "
                        "and host, for example https://dvwa.example.com. The "
                        "crawl is confined to this host by the allow-list.")

    class CollectInjectionPointsTool(BaseTool):
        name: str = "enumerate_endpoints"
        description: str = (
            "Crawls the target web application and returns EVERY request "
            "parameter it accepts, as a JSON list with one row per parameter. "
            "Each row carries: url (full URL including scheme and host), method "
            "(GET or POST), param (exactly one parameter name, never a list), "
            "value (the original value the crawler saw in the form, which is "
            "what tells you whether the parameter looks numeric or string), "
            "siblings (every OTHER field of the same form at its original "
            "value, which must be replayed on every request or the server-side "
            "guard never runs the query), and requires_auth (true when the "
            "crawler was redirected to a login page instead of reaching the "
            "form). This tool ONLY looks. It sends no payloads, it tests "
            "nothing, and it never reports a vulnerability. Call it once at the "
            "start of an assessment to obtain the attack surface, then rank the "
            "rows it returned; do not guess parameter names, and do not call it "
            "again for the same target because the crawl is deterministic and "
            "the result will be identical.")
        args_schema: Type[BaseModel] = CollectInjectionPointsInput
        session: Any = None

        def _run(self, url, run_manager=None):
            import json
            # No try/except on purpose. A crawl that failed must surface as a
            # failure; a plausible-looking empty list would be read downstream
            # as "this application has no parameters", which is a lie.
            points = enumerate_endpoints(url, session=self.session)
            return json.dumps(points, ensure_ascii=False)

        def _arun(self, url, run_manager=None):
            raise NotImplementedError("enumerate_endpoints is synchronous")

    class ConfirmSqliInput(BaseModel):
        url: str = Field(
            description="Full URL of the endpoint to test, scheme and host "
                        "included, copied verbatim from the enumerate_endpoints row.")
        method: str = Field(
            description="GET or POST, copied verbatim from the same row. Sending "
                        "a POST parameter as GET tests nothing.")
        param: str = Field(
            description="The ONE parameter name that will carry the payload.")
        context: str = Field(
            description="numeric, string, or unknown -- your classification of "
                        "what the original value looks like. This selects which "
                        "payload group the tool fires. It is not a verdict.")
        value: str = Field(
            default="",
            description="The parameter's original value from the crawler row. "
                        "Payloads are APPENDED to it, so id=1 is probed as id=1' "
                        "and never as id='. Empty string replaces the value.")
        siblings: Optional[Dict[str, str]] = Field(
            default=None,
            description="The siblings dict from the same crawler row, replayed "
                        "verbatim on every request. Not optional in practice.")

    class ConfirmSqliTool(BaseTool):
        name: str = "evaluate_sqli"
        description: str = (
            "Fires a FIXED, code-owned SQL injection payload set at ONE "
            "parameter of ONE endpoint and returns the evidence it observed. "
            "THIS TOOL DECIDES THE VERDICT AND YOU DO NOT: the boolean it "
            "returns in 'confirmed' is the only thing in this system allowed to "
            "call a parameter vulnerable, and reading a response yourself and "
            "concluding that something looks injectable is not evidence. It "
            "walks three techniques in order and stops at the first "
            "confirmation -- error-based (a known database error signature "
            "appears in the body), boolean-blind (a TRUE payload matches the "
            "baseline while a FALSE payload does not), then time-blind (the "
            "response is at least four seconds slower than baseline, reproduced "
            "twice). It returns confirmed (bool), technique, evidence (the "
            "verbatim observation, never a summary), payload (the exact string "
            "that worked), stage_reached, requests_used, and error. A non-null "
            "error means the attempt could not run at all -- that point is "
            "UNDETERMINED, not safe, and must be reported as not tested. You "
            "never choose the payloads; you only choose which parameter is "
            "worth spending requests on, and you pass along the value and "
            "siblings from the crawler row unchanged.")
        args_schema: Type[BaseModel] = ConfirmSqliInput
        session: Any = None

        def _run(self, url, method, param, context, value="", siblings=None,
                 run_manager=None):
            import json
            # evaluate_sqli already fills the `error` field instead of raising
            # for target-side failures, so anything that escapes it is a bug in
            # our own harness and must propagate.
            result = evaluate_sqli(url, method, param, context, value=value,
                                   siblings=siblings, session=self.session)
            return json.dumps(result, ensure_ascii=False)

        def _arun(self, *a, **kw):
            raise NotImplementedError("evaluate_sqli is synchronous")

    _TOOL_CLASSES = (CollectInjectionPointsTool, ConfirmSqliTool)
    return _TOOL_CLASSES


def build_tools(session):
    """The two custom tools, bound to the run's single Session."""
    collect_cls, confirm_cls = _load_tool_classes()
    return [collect_cls(session=session), confirm_cls(session=session)]


# ---------------------------------------------------------------------------
# The two subagents (requirement 1) -- prompts come from agent/prompts.py
# ---------------------------------------------------------------------------
def _target_vars(target):
    return {**prompts.DVWA, "base_url": target}


def build_subagents(session, target):
    """Triage and report, in the dict format the XSS lecture example uses.

    The system prompts are NOT written here. They are prompts.TRIAGE and
    prompts.REPORT, already written and already tested, filled in with the
    runtime target.
    """
    tools = build_tools(session)
    model = _chat_model(config.SUBAGENT_MODEL)
    tvars = _target_vars(target)
    return [
        {
            "name": "triage",
            "description": (
                "Ranks a list of already-discovered injection points by how "
                "likely each one is to reach a database, and classifies the "
                "context of the ones it ranks high as numeric, string or "
                "unknown so the confirmation tool can select a payload group. "
                "Give it the full parameter list from enumerate_endpoints and "
                "it returns a small ranked subset in labelled blocks. It never "
                "decides whether anything is vulnerable and it never fires a "
                "payload; use it to spend the request budget on the parameters "
                "that are worth it instead of testing the whole attack surface."),
            "system_prompt": prompts.build(prompts.TRIAGE, tvars),
            "tools": tools,
            "model": model,
        },
        {
            "name": "report",
            "description": (
                "Turns the raw results of confirmation attempts into the final "
                "security report. Give it the verdicts returned by "
                "evaluate_sqli, including the ones that were not confirmed and "
                "the ones that errored, and it produces a labelled summary plus "
                "one block per CONFIRMED finding with the evidence quoted "
                "verbatim. It reports only what the tool confirmed, it invents "
                "no file paths or CVE identifiers because it is looking at HTTP "
                "traffic rather than source, and an empty findings list is a "
                "valid result it will state plainly."),
            "system_prompt": prompts.build(prompts.REPORT, tvars),
            "tools": tools,
            "model": model,
        },
    ]


def build_orchestrator(session, target):
    """The full deep agent: orchestrator prompt + both tools + both subagents.

    Not on the pipeline's path -- llm_triage and llm_report drive the two
    subagents directly, one turn each, which is what keeps stage 2 and stage 4
    reproducible. This exists for the demo and for requirement 1. See note 3 in
    the module docstring before you rely on it.
    """
    try:
        from deepagents import create_deep_agent
    except ImportError as exc:
        raise _need("deepagents", exc)
    return create_deep_agent(
        model=_chat_model(config.ORCHESTRATOR_MODEL),
        tools=build_tools(session),
        subagents=build_subagents(session, target),
        system_prompt=prompts.build(prompts.ORCHESTRATOR, _target_vars(target)),
        backend=_backend(),
        skills=[str(SKILLS_DIR)],
    )


# ---------------------------------------------------------------------------
# Running one subagent and getting text back
# ---------------------------------------------------------------------------
def _final_text(response):
    """Pull the last assistant message out of an agent response.

    Bedrock returns content as a list of blocks as often as it returns a
    string, so both shapes are handled. No text at all is a failure, not "".
    """
    messages = None
    if isinstance(response, dict):
        messages = response.get("messages")
    if not messages:
        raise EmptyResponse("agent returned no messages: %r" % (response,))

    content = getattr(messages[-1], "content", None)
    if content is None and isinstance(messages[-1], dict):
        content = messages[-1].get("content")

    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("text"):
                parts.append(block["text"])
        content = "\n".join(parts)

    text = (content or "").strip()
    if not text:
        raise EmptyResponse("agent returned an empty final message")
    return text


def _run_stage(name, system_prompt, user_text, tools, model_id):
    agent = _stage_agent(system_prompt, tools, model_id)
    response = agent.invoke({"messages": [{"role": "user", "content": user_text}]})
    text = _final_text(response)
    _write_raw("%s.txt" % name, text)
    return text


def _write_raw(name, text):
    """Keep the model's own words on disk. When a parse fails at 16:10 this is
    the only thing that tells you why."""
    raw = ARTIFACTS / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / name).write_text(text + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Label parsing. Regex only -- never json.loads() on a model response.
# ---------------------------------------------------------------------------
# Tolerates "URL: x", "  - URL: x", "**URL:** x", "> URL: x", "#### URL: x".
_LABEL_RE = re.compile(r"^[\s>*#\-]*\**\s*([A-Z][A-Z0-9_]{1,30})\**\s*:\s*\**\s*(.*)$")

_TRIAGE_LABELS = ("URL", "METHOD", "PARAM", "PRIORITY", "CONTEXT",
                  "CONTEXT_REASON", "REASON", "REQUIRES_AUTH")
_REPORT_LABELS = ("FINDING_URL", "FINDING_METHOD", "FINDING_PARAM",
                  "FINDING_TECHNIQUE", "FINDING_SEVERITY", "FINDING_EVIDENCE",
                  "FINDING_PAYLOAD", "FINDING_REMEDIATION")

_TRUE_WORDS = ("true", "yes", "y", "1")
_CONTEXTS = ("numeric", "string", "unknown")
_PRIORITIES = ("high", "medium", "low")


def _clean(value):
    """Strip the decoration models put around a label value."""
    v = value.strip()
    while v[-1:] in ("*", "`", " "):
        v = v[:-1].rstrip()
    v = v.strip("`").strip()
    if v.startswith("[") and v.endswith("]"):
        v = v[1:-1].strip()
    return v


def _snippet(text, n=400):
    return text[:n].replace("\n", " | ")


def _int_or_none(value):
    m = re.search(r"-?\d+", value or "")
    return int(m.group(0)) if m else None


def parse_counts(text):
    """TOTAL_POINTS and SELECTED from a triage response. Missing is None, not 0
    -- a model that never printed the count did not count zero."""
    out = {"total_points": None, "selected": None}
    for line in text.splitlines():
        m = _LABEL_RE.match(line)
        if not m:
            continue
        label = m.group(1)
        if label == "TOTAL_POINTS":
            out["total_points"] = _int_or_none(_clean(m.group(2)))
        elif label == "SELECTED":
            out["selected"] = _int_or_none(_clean(m.group(2)))
    return out


def parse_triage(text):
    """Scrape the TRIAGE output format into a list of dicts.

    Keys: url, method, param, priority, context, context_reason, reason,
    requires_auth. A block missing url/method/param is unusable and is dropped
    with a printed warning; if NOTHING survives, this raises. It never returns
    an empty list quietly -- an empty stage 2 would look identical to "the
    application has nothing worth testing", which is a different claim.
    """
    blocks = []
    current = None
    for line in text.splitlines():
        m = _LABEL_RE.match(line)
        if not m:
            continue
        label, value = m.group(1), _clean(m.group(2))
        if label == "URL":
            if current:
                blocks.append(current)
            current = {}
        if current is None or label not in _TRIAGE_LABELS:
            continue
        current[label.lower()] = value
    if current:
        blocks.append(current)

    if not blocks:
        raise ParseFailure(
            "triage response carried no URL: label. Wanted the labels %s. "
            "Model said: %s" % (", ".join(_TRIAGE_LABELS), _snippet(text)))

    out = []
    dropped = 0
    for b in blocks:
        if not (b.get("url") and b.get("method") and b.get("param")):
            dropped += 1
            continue
        context = b.get("context", "").lower()
        priority = b.get("priority", "").lower()
        out.append({
            "url": b["url"],
            "method": b["method"].upper(),
            "param": b["param"],
            "priority": priority if priority in _PRIORITIES else "medium",
            "context": context if context in _CONTEXTS else "unknown",
            "context_reason": b.get("context_reason", ""),
            "reason": b.get("reason", ""),
            "requires_auth": b.get("requires_auth", "").lower() in _TRUE_WORDS,
        })
    if dropped:
        print("    [triage] %d block(s) dropped: no URL/METHOD/PARAM" % dropped)
    if not out:
        raise ParseFailure(
            "triage produced %d block(s) and not one carried URL, METHOD and "
            "PARAM together. Model said: %s" % (len(blocks), _snippet(text)))
    return out


def parse_report(text):
    """Scrape the REPORT output format.

    Returns {"summary": str, "points_tested": int|None,
             "confirmed_count": int|None, "findings": [ {...}, ... ]}
    with finding keys url/method/param/technique/severity/evidence/payload/
    remediation. Raises when neither a SUMMARY nor a single FINDING_URL block
    is present -- that is a parse failure, not a clean report.
    """
    summary_lines = []
    findings = []
    current = None
    last_key = None       # which multi-line field a bare line continues

    for line in text.splitlines():
        m = _LABEL_RE.match(line)
        if not m:
            stripped = line.strip()
            if not stripped:
                last_key = None
            elif last_key == "SUMMARY":
                summary_lines.append(stripped)
            elif last_key and current is not None:
                current[last_key.lower()] = (
                    (current.get(last_key.lower(), "") + " " + stripped).strip())
            continue

        label, value = m.group(1), _clean(m.group(2))
        last_key = label
        if label == "SUMMARY":
            if value:
                summary_lines.append(value)
            continue
        if label == "FINDING_URL":
            if current:
                findings.append(current)
            current = {}
        if label in _REPORT_LABELS and current is not None:
            current[label.lower()] = value
    if current:
        findings.append(current)

    summary = " ".join(summary_lines).strip()
    counts = {"points_tested": None, "confirmed_count": None}
    for line in text.splitlines():
        m = _LABEL_RE.match(line)
        if not m:
            continue
        if m.group(1) == "POINTS_TESTED":
            counts["points_tested"] = _int_or_none(_clean(m.group(2)))
        elif m.group(1) == "CONFIRMED_COUNT":
            counts["confirmed_count"] = _int_or_none(_clean(m.group(2)))

    if not summary and not findings:
        raise ParseFailure(
            "report response carried neither SUMMARY: nor FINDING_URL:. Wanted "
            "SUMMARY, POINTS_TESTED, CONFIRMED_COUNT and FINDING_* blocks. "
            "Model said: %s" % _snippet(text))

    out = []
    for f in findings:
        if not f.get("finding_url"):
            continue
        out.append({
            "url": f.get("finding_url", ""),
            "method": f.get("finding_method", "").upper(),
            "param": f.get("finding_param", ""),
            "technique": f.get("finding_technique", ""),
            "severity": f.get("finding_severity", ""),
            "evidence": f.get("finding_evidence", ""),
            "payload": f.get("finding_payload", ""),
            "remediation": f.get("finding_remediation", ""),
        })
    return {"summary": summary, "points_tested": counts["points_tested"],
            "confirmed_count": counts["confirmed_count"], "findings": out}


# ---------------------------------------------------------------------------
# Hallucination guard: everything the model names must exist in our own data
# ---------------------------------------------------------------------------
def _key(url, method, param):
    """(url, method, param) normalised enough to survive a model retyping it.

    Scheme and host lowercased, query and fragment dropped, one trailing slash
    tolerated. Nothing else -- a different path is a different endpoint.
    """
    p = urlparse((url or "").strip())
    host = (p.netloc or "").lower()
    scheme = (p.scheme or "").lower()
    path = (p.path or "/").rstrip("/") or "/"
    return ("%s://%s%s" % (scheme, host, path),
            (method or "").strip().upper(),
            (param or "").strip())


def _match_point(points, url, method, param):
    for p in points:
        if _key(p["url"], p["method"], p["param"]) == _key(url, method, param):
            return p
    return None


# ---------------------------------------------------------------------------
# Stage 2
# ---------------------------------------------------------------------------
def _format_points(points):
    lines = []
    for i, p in enumerate(points, 1):
        lines += [
            "POINT %d" % i,
            "  url: %s" % p["url"],
            "  method: %s" % p["method"],
            "  param: %s" % p["param"],
            "  original_value: %s" % (p.get("value") or "(empty)"),
            "  sibling_fields: %s" % (", ".join(p.get("siblings") or {}) or "(none)"),
            "  requires_auth: %s" % ("true" if p.get("requires_auth") else "false"),
        ]
    return "\n".join(lines)


def llm_triage(points, target, session):
    """Stage 2 via the triage subagent.

    Same return shape as pipeline.stage2_triage: the original point dicts with
    priority, context, context_reason and reason added. value and siblings come
    from the crawler row, always, never from the model.
    """
    if not points:
        raise ValueError("llm_triage got no injection points to rank")

    user_text = (
        "Here are the %d injection points discovered on %s by "
        "enumerate_endpoints. They are the complete list; do not add to it and "
        "do not call any tool to rediscover it.\n\n%s\n\n"
        "Rank them and select AT MOST %d to test. Answer using the labelled "
        "output format from your instructions, one block per selected "
        "parameter, copying url, method and param exactly as written above."
        % (len(points), target, _format_points(points), config.MAX_CANDIDATES))

    tvars = _target_vars(target)
    text = _run_stage("02_triage", prompts.build(prompts.TRIAGE, tvars),
                      user_text, build_tools(session), config.SUBAGENT_MODEL)

    counts = parse_counts(text)
    blocks = parse_triage(text)
    if counts["total_points"] is not None and counts["total_points"] != len(points):
        print("    [triage] model said TOTAL_POINTS=%s, we sent %d"
              % (counts["total_points"], len(points)))
    if counts["selected"] is not None and counts["selected"] != len(blocks):
        print("    [triage] model said SELECTED=%s, parsed %d block(s)"
              % (counts["selected"], len(blocks)))

    candidates = []
    seen = set()
    invented = 0
    for b in blocks:
        point = _match_point(points, b["url"], b["method"], b["param"])
        if point is None:
            invented += 1
            print("    [triage] discarded %s %s param=%s - not in the crawl"
                  % (b["method"], b["url"], b["param"]))
            continue
        k = _key(point["url"], point["method"], point["param"])
        if k in seen:
            continue
        seen.add(k)
        # dict(point, ...) first: value, siblings and requires_auth are the
        # crawler's facts and the model does not get a vote on them.
        candidates.append(dict(point,
                               priority=b["priority"],
                               context=b["context"],
                               context_reason=b["context_reason"],
                               reason=b["reason"]))

    if not candidates:
        raise ParseFailure(
            "triage selected %d point(s) and every one of them was invented "
            "(not present in the %d crawled points). Raw response is in "
            "artifacts/raw/02_triage.txt" % (invented, len(points)))

    order = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(key=lambda c: order.get(c["priority"], 1))
    return candidates[:config.MAX_CANDIDATES]


# ---------------------------------------------------------------------------
# Stage 4
# ---------------------------------------------------------------------------
def _format_verdicts(verdicts):
    lines = []
    for i, v in enumerate(verdicts, 1):
        lines += [
            "RESULT %d" % i,
            "  url: %s" % v["url"],
            "  method: %s" % v["method"],
            "  param: %s" % v["param"],
            "  context_tested: %s" % v.get("context", ""),
            "  confirmed: %s" % ("true" if v["confirmed"] else "false"),
            "  technique: %s" % v["technique"],
            "  payload: %s" % (v["payload"] or "(none)"),
            "  evidence: %s" % (v["evidence"] or "(none)"),
            "  stage_reached: %s" % v["stage_reached"],
            "  requests_used: %s" % v["requests_used"],
            "  error: %s" % (v["error"] or "none"),
        ]
    return "\n".join(lines)


def _write(name, text):
    ARTIFACTS.mkdir(exist_ok=True)
    (ARTIFACTS / name).write_text(text + "\n", encoding="utf-8")
    print("  wrote artifacts/%s" % name)


def llm_report(verdicts, target, session, points=None, elapsed=None):
    """Stage 4 via the report subagent.

    Same contract as pipeline.stage4_report: writes artifacts/05_report.md and
    artifacts/02_threat_model.md, returns None. `points` and `elapsed` are
    optional extras so the header can quote the full attack surface and the
    wall time; without them the report still stands.

    A finding the model prints for a verdict that is not confirmed=true in our
    own data is dropped. The tool decides, not the model -- this is the last
    place that rule is enforced.
    """
    if not verdicts:
        raise ValueError("llm_report got no verdicts to write up")

    user_text = (
        "These are the raw confirmation results for %s. Every one came from the "
        "evaluate_sqli tool, which sent the requests and observed the "
        "responses.\n\n%s\n\nWrite the report using the labelled output format "
        "from your instructions. Only results with confirmed: true become "
        "FINDING_* blocks. Quote the evidence field verbatim."
        % (target, _format_verdicts(verdicts)))

    tvars = _target_vars(target)
    text = _run_stage("04_report", prompts.build(prompts.REPORT, tvars),
                      user_text, build_tools(session), config.SUBAGENT_MODEL)
    parsed = parse_report(text)

    confirmed = [v for v in verdicts if v["confirmed"]]
    errored = [v for v in verdicts if v["error"]]

    # Pair each model finding with the verdict it claims to describe.
    paired = []
    for f in parsed["findings"]:
        match = None
        for v in confirmed:
            if _key(v["url"], v["method"], v["param"]) == _key(
                    f["url"], f["method"], f["param"]):
                match = v
                break
        if match is None:
            print("    [report] discarded finding %s %s param=%s - no confirmed "
                  "verdict for it" % (f["method"], f["url"], f["param"]))
            continue
        paired.append((match, f))

    covered = {_key(v["url"], v["method"], v["param"]) for v, _ in paired}
    missed = [v for v in confirmed
              if _key(v["url"], v["method"], v["param"]) not in covered]
    for v in missed:
        print("    [report] model omitted confirmed finding %s %s param=%s - "
              "added from the verdict" % (v["method"], v["url"], v["param"]))
        paired.append((v, None))

    if parsed["confirmed_count"] is not None and \
            parsed["confirmed_count"] != len(confirmed):
        print("    [report] model said CONFIRMED_COUNT=%s, tool confirmed %d"
              % (parsed["confirmed_count"], len(confirmed)))

    total_points = len(points) if points is not None else len(verdicts)
    out = ["# SQL injection assessment - %s" % target, "",
           "%d injection points enumerated, %d tested, **%d confirmed**."
           % (total_points, len(verdicts), len(confirmed))]
    if elapsed is not None:
        out.append("Wall time %.1fs." % elapsed)
    out += ["", "## Summary", "", parsed["summary"] or
            "(the model returned no SUMMARY line; see artifacts/raw/04_report.txt)",
            ""]

    out.append("## Confirmed findings")
    if paired:
        for v, f in paired:
            severity = (f or {}).get("severity") or "high"
            remediation = (f or {}).get("remediation") or (
                "Bind this parameter as a query placeholder. In PHP, "
                "mysqli_prepare with bind_param, never string concatenation.")
            out += ["", "### %s `%s` (%s)" % (v["method"], v["param"], v["technique"]),
                    "", "- URL: %s" % v["url"],
                    "- Severity: %s" % severity,
                    "- Payload: `%s`" % v["payload"],
                    "- Requests used: %d" % v["requests_used"],
                    # Evidence is the tool's string, not the model's retyping of
                    # it. The model may summarise; the artifact may not.
                    "- Evidence: %s" % v["evidence"],
                    "- Fix: %s" % remediation]
    else:
        out += ["", "None. An empty findings list is a valid result and is not "
                "the same as a clean application."]

    if errored:
        out += ["", "## Not tested", ""]
        out += ["- %s `%s` - %s" % (v["url"], v["param"], v["error"])
                for v in errored]
        out += ["", "These were never reached, which is undetermined, not safe."]
    out += ["", "---", "",
            "Stage 2 and stage 4 were written by %s via Bedrock. Every "
            "`confirmed` flag above came from core/verdict.py, which no model "
            "can reach." % config.SUBAGENT_MODEL]
    _write("05_report.md", "\n".join(out))

    # See note 5 in the module docstring: this is the stub's structure with the
    # model's summary on top, not yet its own LLM call.
    entry_points = points if points is not None else verdicts
    tm = ["# Threat model - %s" % target, "", parsed["summary"] or
          "(no model summary available)", "", "## Entry points", ""]
    tm += ["- %s `%s` on %s" % (p["method"], p["param"], p["url"])
           for p in entry_points]
    tm += ["", "## Trust boundary", "",
           "The browser sends parameters; PHP interpolates them into SQL and "
           "MariaDB executes the result. The boundary that matters sits between "
           "the request and the query string, and every confirmed finding below "
           "crossed it.", "",
           "## What an attacker gains from a confirmed CWE-89 here", "",
           "- Read any table the web user can reach, including the credentials table",
           "- Bypass authentication where the injected parameter is part of a login test",
           "- Depending on grants and secure_file_priv, write files and reach code execution",
           "", "## Confirmed crossings", ""]
    tm += (["- %s `%s` via %s" % (v["url"], v["param"], v["technique"])
            for v in confirmed] or ["- none confirmed in this run"])
    _write("02_threat_model.md", "\n".join(tm))


if __name__ == "__main__":
    # Offline self-check: the parsers are pure, so they run with nothing
    # installed. This is the only part of this file that has been executed.
    sample_triage = (
        "TOTAL_POINTS: 12\n"
        "SELECTED: 2\n"
        "\n"
        "URL: http://localhost:8080/vulnerabilities/sqli/\n"
        "METHOD: GET\n"
        "PARAM: id\n"
        "PRIORITY: high\n"
        "CONTEXT: numeric\n"
        "CONTEXT_REASON: original value 1 is digits only\n"
        "REASON: record lookup by identifier\n"
        "REQUIRES_AUTH: true\n"
        "\n"
        "**URL:** http://localhost:8080/vulnerabilities/sqli_blind/\n"
        "**METHOD:** GET\n"
        "**PARAM:** id\n"
        "**PRIORITY:** high\n"
        "**CONTEXT:** numeric\n"
        "**CONTEXT_REASON:** looks like an integer\n"
        "**REASON:** blind variant of the same lookup\n"
        "**REQUIRES_AUTH:** true\n")
    print("parse_counts:", parse_counts(sample_triage))
    for row in parse_triage(sample_triage):
        print("  triage row:", row)

    sample_report = (
        "SUMMARY: Two parameters reach the database without binding.\n"
        "The application is exploitable without authentication bypass.\n"
        "POINTS_TESTED: 6\n"
        "CONFIRMED_COUNT: 1\n"
        "\n"
        "FINDING_URL: http://localhost:8080/vulnerabilities/sqli/\n"
        "FINDING_METHOD: GET\n"
        "FINDING_PARAM: id\n"
        "FINDING_TECHNIQUE: error-based\n"
        "FINDING_SEVERITY: critical\n"
        "FINDING_EVIDENCE: You have an error in your SQL syntax\n"
        "FINDING_PAYLOAD: '\n"
        "FINDING_REMEDIATION: Use mysqli_prepare with bind_param.\n")
    parsed_report = parse_report(sample_report)
    print("parse_report summary:", parsed_report["summary"])
    print("parse_report findings:", parsed_report["findings"])

    for bad, label in (("the parameter looks fine to me", "triage"),
                       ("no labels at all here", "report")):
        try:
            parse_triage(bad) if label == "triage" else parse_report(bad)
        except ParseFailure as exc:
            print("ParseFailure (%s) raised as designed: %s" % (label, str(exc)[:70]))
        else:
            raise SystemExit("FAIL: %s parser accepted unlabelled text" % label)
    print("parser self-check OK")
