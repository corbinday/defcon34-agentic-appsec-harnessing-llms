"""The 4-stage chain. OWNER: Mike.

Stages 1 and 3 are tool-run, per AGENTS.md section 3: deterministic Python,
because consistency (requirement 6) depends on the crawl and the payload firing
never varying with the model. Stages 2 and 4 are LLM-run: real Bedrock calls
through a deepagents subagent, driven by the prompts in agent/prompts.py.

    1 Enumerate  tool   ->  every parameter the app accepts
    2 Triage     LLM    ->  ranked subset + numeric/string context
    3 Confirm    tool   ->  a verdict carrying evidence
    4 Report     LLM    ->  report + threat model

Stage 2 never decides whether anything is vulnerable -- its output is joined
back against the stage-1 rows by (url, method, param) so the LLM cannot smuggle
an invented value or sibling into what gets sent. Stage 3 is the only thing
that sets `confirmed`. Stage 4 reports only findings stage 3 actually
confirmed -- the LLM supplies severity and remediation prose, never the verdict
itself.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

# Run as a script (python agent/pipeline.py) or as a module (python -m
# agent.pipeline). The first form puts agent/ on sys.path instead of the repo
# root, so the package imports below would fail without this.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from deepagents import create_deep_agent  # noqa: E402
from deepagents.backends import FilesystemBackend  # noqa: E402
from langchain_aws import ChatBedrockConverse  # noqa: E402

from agent import config  # noqa: E402
from agent import prompts  # noqa: E402
from core.browser import enumerate_endpoints  # noqa: E402
from core.prober import evaluate_sqli  # noqa: E402
from core.session import Session  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts"
SKILLS_DIR = str(ROOT / "skills")

LABEL_RE = re.compile(r"^([A-Z_]+):\s*(.*)$")


def _run_subagent(system_prompt, user_content, use_skills, model_id):
    """One-shot call to a real Bedrock model through create_deep_agent.

    No tools -- these two subagents reason over data the harness already
    collected, they do not go fetch more of it. `backend` still needs to point
    at the repo root even without tools, or skill loading raises ValueError
    the moment `skills` is non-empty (see AGENTS.md section 7, Mike's trap).
    """
    llm = ChatBedrockConverse(model_id=model_id, temperature=0)
    agent = create_deep_agent(
        model=llm,
        tools=[],
        system_prompt=system_prompt,
        backend=FilesystemBackend(root_dir=ROOT, virtual_mode=False),
        skills=[SKILLS_DIR] if use_skills else None,
    )
    result = agent.invoke({"messages": [{"role": "user", "content": user_content}]})
    return result["messages"][-1].content


def _parse_labeled_blocks(text, block_start_key):
    """ENGLISH CAPITALS `KEY: value` lines, as agent/prompts.py specifies.

    Lines before the first `block_start_key` are the header (e.g. SUMMARY);
    each `block_start_key` line opens a new block. Never json.loads() a raw
    LLM response -- this is the label-regex fallback the coding rules call
    for, and it is the only parse path here, not a fallback from a first one.
    """
    header, blocks = {}, []
    current = None
    for line in text.splitlines():
        m = LABEL_RE.match(line.strip())
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if key == block_start_key:
            if current is not None:
                blocks.append(current)
            current = {}
        if current is None:
            header[key] = val
        else:
            current[key] = val
    if current is not None:
        blocks.append(current)
    return header, blocks


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


def stage2_triage(points, target):
    """Real triage subagent: ranks and labels context. Never sets a verdict.

    The LLM's PRIORITY/CONTEXT/REASON labels are trusted. Its URL/METHOD/PARAM
    are only a lookup key back into `points` -- the row that actually ships to
    stage 3 (value, siblings) always comes from the crawl, never from the
    model's echo of it. That is what keeps an invented sibling from reaching
    evaluate_sqli and silently breaking DVWA's isset() guard.
    """
    system_prompt = prompts.build(prompts.TRIAGE, {**prompts.DVWA, "base_url": target})
    lines = ["TOTAL_POINTS: %d" % len(points), ""]
    for p in points:
        lines += ["URL: %s" % p["url"], "METHOD: %s" % p["method"],
                   "PARAM: %s" % p["param"], "VALUE: %r" % p["value"],
                   "SIBLINGS: %s" % (", ".join(p["siblings"]) or "(none)"),
                   "REQUIRES_AUTH: %s" % p["requires_auth"], ""]
    text = _run_subagent(system_prompt, "\n".join(lines),
                         use_skills=True, model_id=config.SUBAGENT_MODEL)

    _, blocks = _parse_labeled_blocks(text, "URL")
    if not blocks:
        raise RuntimeError("triage: no parseable labeled blocks in LLM output:\n" + text)

    by_key = {(p["url"], p["method"], p["param"]): p for p in points}
    candidates = []
    for b in blocks:
        key = (b.get("URL"), b.get("METHOD"), b.get("PARAM"))
        orig = by_key.get(key)
        if orig is None:
            continue  # the model named a point outside the crawl -- ignore, never invent one
        candidates.append(dict(orig,
                               priority=b.get("PRIORITY", "medium").lower(),
                               context=b.get("CONTEXT", "unknown").lower(),
                               context_reason=b.get("CONTEXT_REASON", ""),
                               reason=b.get("REASON", "")))
    if not candidates:
        raise RuntimeError("triage: parsed blocks matched none of the enumerated points")
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
    """Real report subagent, plus a separate LLM call for the threat model.

    The LLM supplies prose: severity, remediation wording, trust-boundary
    description. Whether a finding is listed at all is decided here, from
    `verdicts`, not from what the model chose to narrate -- a confirmed hit the
    model's text skipped still gets appended, and a "finding" the model
    invented for a point that was never confirmed is dropped.
    """
    hits = [v for v in verdicts if v["confirmed"]]
    errs = [v for v in verdicts if v["error"]]
    by_key = {(v["url"], v["method"], v["param"]): v for v in hits}

    system_prompt = prompts.build(prompts.REPORT, {**prompts.DVWA, "base_url": target})
    lines = ["POINTS_TESTED: %d" % len(verdicts), "CONFIRMED_COUNT: %d" % len(hits), ""]
    for v in verdicts:
        lines += ["URL: %s" % v["url"], "METHOD: %s" % v["method"],
                   "PARAM: %s" % v["param"], "CONFIRMED: %s" % v["confirmed"],
                   "TECHNIQUE: %s" % v["technique"], "EVIDENCE: %s" % v["evidence"],
                   "PAYLOAD: %s" % v["payload"], "ERROR: %s" % v["error"], ""]
    text = _run_subagent(system_prompt, "\n".join(lines),
                         use_skills=False, model_id=config.SUBAGENT_MODEL)
    header, blocks = _parse_labeled_blocks(text, "FINDING_URL")

    out = ["# SQL injection assessment - %s" % target, "",
           header.get("SUMMARY") or ("%d injection points enumerated, %d tested, "
                                     "**%d confirmed**." % (len(points), len(verdicts), len(hits))),
           "Wall time %.1fs." % elapsed, ""]

    def _finding_block(v, severity="high", remediation=None):
        return ["", "### %s `%s` (%s)" % (v["method"], v["param"], v["technique"]),
                "", "- URL: %s" % v["url"],
                "- Payload: `%s`" % v["payload"],
                "- Requests used: %d" % v["requests_used"],
                "- Evidence: %s" % v["evidence"],
                "- Severity: %s" % severity,
                "- Fix: %s" % (remediation or "Bind this parameter as a query "
                               "placeholder. In PHP, `mysqli_prepare` with "
                               "`bind_param`, never string concatenation.")]

    if hits:
        out.append("## Confirmed findings")
        narrated = set()
        for b in blocks:
            key = (b.get("FINDING_URL"), b.get("FINDING_METHOD"), b.get("FINDING_PARAM"))
            v = by_key.get(key)
            if v is None:
                continue  # the model narrated a "finding" stage 3 never confirmed
            narrated.add(key)
            out += _finding_block(v, b.get("FINDING_SEVERITY", "high"),
                                  b.get("FINDING_REMEDIATION"))
        for v in hits:
            key = (v["url"], v["method"], v["param"])
            if key not in narrated:  # confirmed by the tool but skipped by the model's prose
                out += _finding_block(v)
    else:
        out += ["## Confirmed findings", "", "None. An empty findings list is a "
                "valid result and is not the same as a clean application."]
    if errs:
        out += ["", "## Not tested", ""]
        out += ["- %s `%s` - %s" % (v["url"], v["param"], v["error"]) for v in errs]
        out += ["", "These were never reached, which is undetermined, not safe."]
    _write("05_report.md", "\n".join(out))
    _write_threat_model(target, points, hits)


def _write_threat_model(target, points, hits):
    system_prompt = prompts.build(prompts.THREAT_MODEL, {**prompts.DVWA, "base_url": target})
    lines = ["ENTRY_POINTS:"]
    lines += ["- %s %s %s" % (p["method"], p["param"], p["url"]) for p in points]
    lines += ["", "CONFIRMED_FINDINGS:"]
    lines += (["- %s %s %s via %s" % (v["method"], v["param"], v["url"], v["technique"])
               for v in hits] or ["- none confirmed in this run"])
    text = _run_subagent(system_prompt, "\n".join(lines),
                         use_skills=False, model_id=config.SUBAGENT_MODEL)

    # A missing crossing in the model's prose is a bug in the report, not a
    # missing vulnerability -- append anything it dropped rather than trust
    # the narrative to have been complete.
    missing = [v for v in hits if v["url"] not in text]
    if missing:
        text = text.rstrip("\n") + "\n" + "\n".join(
            "- %s `%s` via %s (appended: not in the model's draft)"
            % (v["url"], v["param"], v["technique"]) for v in missing) + "\n"
    _write("02_threat_model.md", text)


def _write(name, text):
    ARTIFACTS.mkdir(exist_ok=True)
    (ARTIFACTS / name).write_text(text + "\n", encoding="utf-8")
    print("  wrote artifacts/%s" % name)


def run(target, max_requests=None):
    started = time.time()
    session = Session(target, config.ALLOWED_TARGETS,
                      max_requests=max_requests or config.MAX_REQUESTS,
                      delay=config.REQUEST_DELAY_SEC, timeout=config.HTTP_TIMEOUT_SEC)
    print("[0] login")
    if not session.login(**config.DVWA_CREDS):
        raise SystemExit("login failed - check the target and the credentials")

    print("[1] enumerate")
    points = stage1_enumerate(session, target)
    print("    %d injection points" % len(points))

    print("[2] triage")
    candidates = stage2_triage(points, target)
    print("    %d of %d selected" % (len(candidates), len(points)))

    print("[3] confirm")
    verdicts = stage3_confirm(session, candidates)

    elapsed = time.time() - started
    print("[4] report")
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
    a = ap.parse_args()
    run(a.target, a.max_requests)
