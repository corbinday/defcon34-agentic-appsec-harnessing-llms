"""The 4-stage chain. OWNER: Mike.

**Stages 2 and 4 have two implementations.** By default they are deterministic
Python stand-ins, so the whole chain completes and produces artifacts on a
laptop with no agent stack and no AWS credentials. Pass **--llm** and they run
through agent/deep_agent.py instead: `create_deep_agent(...)` with a triage
subagent and a report subagent, driven by the prompts already written in
agent/prompts.py. The stubs stay as the fallback -- do not delete them.

    python agent/pipeline.py --target URL          stubs, works offline
    python agent/pipeline.py --target URL --llm    deep agent, needs Bedrock

The seam is deliberate. Stage 2 has one job -- turn a list of points into a
ranked subset with a context label -- and stage 4 has one job: turn verdicts into
markdown. Swap either one without touching stages 1 and 3.

    1 Enumerate  tool   ->  every parameter the app accepts
    2 Triage     LLM    ->  ranked subset + numeric/string context      <- stand-in
    3 Confirm    tool   ->  a verdict carrying evidence
    4 Report     LLM    ->  report + threat model                       <- stand-in

Stage 2 never decides whether anything is vulnerable. Stage 3 is the only thing
that sets `confirmed`.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Run as a script (python agent/pipeline.py) or as a module (python -m
# agent.pipeline). The first form puts agent/ on sys.path instead of the repo
# root, so the package imports below would fail without this.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import config  # noqa: E402
from core.browser import enumerate_endpoints  # noqa: E402
from core.prober import evaluate_sqli  # noqa: E402
from core.session import Session  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts"

# Names that historically reach a database. The real triage subagent reads
# skills/endpoint-discovery/SKILL.md and reasons about this instead.
HIGH = ("id", "uid", "user_id", "pid", "no", "seq", "idx",
        "q", "search", "keyword", "query", "filter",
        "sort", "order", "orderby", "limit", "offset", "username", "user")
CONTROL = ("submit", "login", "user_token", "csrf_token", "_method", "seclev_submit")


def stage1_enumerate(session, target):
    points = enumerate_endpoints(target, session=session)
    lines = ["# Context: attack surface of %s" % target, "",
             "Collected by `enumerate_endpoints` before anything was tested.",
             "", "| # | Method | URL | Parameter | Value | Siblings replayed |",
             "|---|---|---|---|---|---|"]
    for i, p in enumerate(points, 1):
        lines.append("| %d | %s | %s | `%s` | `%s` | %s |" % (
            i, p["method"], p["url"], p["param"], p["value"] or "(empty)",
            ", ".join("`%s`" % s for s in p["siblings"]) or "-"))
    lines += ["", "%d injection points across %d endpoints." % (
        len(points), len({p["url"] for p in points}))]
    _write("01_context.md", "\n".join(lines))
    return points


def stage2_triage(points):
    """STAND-IN for the triage subagent. Ranks and labels context. No verdicts."""
    candidates = []
    for p in points:
        name = p["param"].lower()
        if name in CONTROL:
            continue
        priority = "high" if name in HIGH else "medium"
        value = (p["value"] or "").strip()
        if value.isdigit():
            context, why = "numeric", "original value %r is digits only" % value
        elif value:
            context, why = "string", "original value %r contains non-digits" % value
        else:
            context, why = "unknown", "no original value seen; treated as string"
        candidates.append(dict(p, priority=priority, context=context,
                               context_reason=why,
                               reason="parameter name suggests a record lookup"
                                      if priority == "high" else "ordinary form field"))
    candidates.sort(key=lambda c: 0 if c["priority"] == "high" else 1)
    return candidates[:config.MAX_CANDIDATES]


def stage3_confirm(session, candidates):
    verdicts = []
    for c in candidates:
        r = evaluate_sqli(c["url"], c["method"], c["param"], c["context"],
                          value=c["value"], siblings=c["siblings"], session=session)
        verdicts.append(dict(c, **r))
        mark = "CONFIRMED" if r["confirmed"] else ("ERROR" if r["error"] else "clean")
        print("  [%-9s] %s %s  param=%s  stage=%s  requests=%d"
              % (mark, c["method"], c["url"], c["param"],
                 r["stage_reached"], r["requests_used"]))
    return verdicts


def stage4_report(target, points, verdicts, elapsed):
    """STAND-IN for the report subagent. Quotes evidence, invents nothing."""
    hits = [v for v in verdicts if v["confirmed"]]
    errs = [v for v in verdicts if v["error"]]

    out = ["# SQL injection assessment - %s" % target, "",
           "%d injection points enumerated, %d tested, **%d confirmed**."
           % (len(points), len(verdicts), len(hits)),
           "Wall time %.1fs." % elapsed, ""]
    if hits:
        out.append("## Confirmed findings")
        for v in hits:
            out += ["", "### %s `%s` (%s)" % (v["method"], v["param"], v["technique"]),
                    "", "- URL: %s" % v["url"],
                    "- Payload: `%s`" % v["payload"],
                    "- Requests used: %d" % v["requests_used"],
                    "- Evidence: %s" % v["evidence"],
                    "- Fix: bind this parameter as a query placeholder. In PHP, "
                    "`mysqli_prepare` with `bind_param`, never string concatenation."]
    else:
        out += ["## Confirmed findings", "", "None. An empty findings list is a "
                "valid result and is not the same as a clean application."]
    if errs:
        out += ["", "## Not tested", ""]
        out += ["- %s `%s` - %s" % (v["url"], v["param"], v["error"]) for v in errs]
        out += ["", "These were never reached, which is undetermined, not safe."]
    _write("05_report.md", "\n".join(out))

    tm = ["# Threat model - %s" % target, "",
          "## Entry points", ""]
    tm += ["- %s `%s` on %s" % (p["method"], p["param"], p["url"]) for p in points]
    tm += ["", "## Trust boundary", "",
           "The browser sends parameters; PHP interpolates them into SQL and MariaDB "
           "executes the result. The boundary that matters sits between the request "
           "and the query string, and every confirmed finding below crossed it.", "",
           "## What an attacker gains from a confirmed CWE-89 here", "",
           "- Read any table the web user can reach, including the credentials table",
           "- Bypass authentication where the injected parameter is part of a login test",
           "- Depending on grants and secure_file_priv, write files and reach code execution",
           "", "## Confirmed crossings", ""]
    tm += (["- %s `%s` via %s" % (v["url"], v["param"], v["technique"]) for v in hits]
           or ["- none confirmed in this run"])
    _write("02_threat_model.md", "\n".join(tm))


def _write(name, text):
    ARTIFACTS.mkdir(exist_ok=True)
    (ARTIFACTS / name).write_text(text + "\n", encoding="utf-8")
    print("  wrote artifacts/%s" % name)


def _llm_stages():
    """Load the deep agent. Imported here, not at module scope, so the default
    (stub) path keeps running on a laptop with no agent stack installed."""
    try:
        from agent.deep_agent import llm_report, llm_triage, preflight
        preflight()          # raises now, before stage 1 spends a request
    except Exception as exc:
        raise SystemExit(
            "--llm cannot run here:\n%s\n"
            "Without --llm the pipeline runs stages 2 and 4 as Python stubs, "
            "which needs none of the above." % exc)
    return llm_triage, llm_report


def run(target, max_requests=None, use_llm=False):
    started = time.time()
    # Fail before the first request if --llm cannot be honoured. Discovering a
    # missing dependency after stage 3 has spent the request budget is the worst
    # possible time to discover it.
    llm_triage, llm_report = _llm_stages() if use_llm else (None, None)

    session = Session(target, config.ALLOWED_TARGETS,
                      max_requests=max_requests or config.MAX_REQUESTS,
                      delay=config.REQUEST_DELAY_SEC, timeout=config.HTTP_TIMEOUT_SEC)
    print("[0] login")
    if not session.login(**config.DVWA_CREDS):
        raise SystemExit("login failed - check the target and the credentials")

    print("[1] enumerate")
    points = stage1_enumerate(session, target)
    print("    %d injection points" % len(points))

    print("[2] triage%s" % (" (LLM)" if use_llm else " (stub)"))
    candidates = (llm_triage(points, target, session) if use_llm
                  else stage2_triage(points))
    print("    %d of %d selected" % (len(candidates), len(points)))

    print("[3] confirm")
    verdicts = stage3_confirm(session, candidates)

    elapsed = time.time() - started
    print("[4] report%s" % (" (LLM)" if use_llm else " (stub)"))
    if use_llm:
        llm_report(verdicts, target, session, points=points, elapsed=elapsed)
    else:
        stage4_report(target, points, verdicts, elapsed)

    summary = {"target": target, "points_total": len(points),
               "points_tested": len(verdicts), "requests_used": session.requests_used,
               "elapsed_sec": round(elapsed, 1),
               "findings": [{"url": v["url"], "method": v["method"], "param": v["param"],
                             "vulnerable": v["confirmed"], "technique": v["technique"],
                             "payload": v["payload"], "evidence": v["evidence"],
                             "error": v["error"]} for v in verdicts]}
    _write("03_findings.json", json.dumps(summary, indent=2, ensure_ascii=False))
    print("    %d confirmed, %d requests, %.1fs"
          % (sum(1 for v in verdicts if v["confirmed"]), session.requests_used, elapsed))
    return summary


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=config.DEFAULT_TARGET)
    ap.add_argument("--max-requests", type=int, default=None)
    ap.add_argument("--llm", action="store_true",
                    help="run stages 2 and 4 through the deep agent "
                         "(agent/deep_agent.py) instead of the Python stubs. "
                         "Needs 'pip install -r requirements.txt' plus AWS "
                         "credentials; without it the stubs run as before.")
    a = ap.parse_args()
    run(a.target, a.max_requests, use_llm=a.llm)
