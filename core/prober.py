"""evaluate_sqli -- fire the fixed payload set at one parameter, report evidence.

OWNER: tprud9412.

Raw HTTP on purpose. Playwright renders, and rendering adds variance to exactly
the two signals we depend on: response size for boolean-blind and wall time for
time-blind. Stage 1 uses a browser; this does not.

Stages run 1 -> 2 -> 3 and stop at the first confirmation. error-based costs four
requests; time-blind costs five seconds each. Ordering is a cost decision, not a
stylistic one.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from core import verdict as V

# The payload set lives beside its SKILL.md so the skill travels as one folder.
# That directory has a hyphen in its name, so it cannot be imported by name.
_PAYLOADS_PATH = (Path(__file__).resolve().parent.parent
                  / "skills" / "sqli-payloads" / "scripts" / "payloads.py")
_spec = importlib.util.spec_from_file_location("sqli_payloads", _PAYLOADS_PATH)
payloads = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(payloads)

# Used when the crawler saw no original value. "1" because record lookups are
# the parameters we rank highest, and 1 is the row every fixture table has.
SEED_VALUE = "1"


def _send(session, url, method, param, value, siblings):
    """One request with `param` set to `value` and every sibling field replayed.

    Dropping the siblings is how you get a silent false negative: DVWA guards the
    query with isset($_GET['Submit']), so the injected parameter alone produces a
    200 with no query executed at all.
    """
    data = dict(siblings or {})
    data[param] = value
    if method.upper() == "POST":
        return session.post(url, data=data)
    return session.get(url, params=data)


def _result(confirmed, technique, evidence, payload, stage, used, error=None):
    return {"confirmed": confirmed, "technique": technique, "evidence": evidence,
            "payload": payload, "stage_reached": stage, "requests_used": used,
            "error": error}


def evaluate_sqli(url, method, param, context, value="", siblings=None, session=None):
    if session is None:
        raise ValueError("evaluate_sqli needs a core.session.Session")
    start = session.requests_used
    used = lambda: session.requests_used - start

    # An empty form field gives us a baseline of "no such record", and against
    # that baseline the boolean test inverts: the TRUE payload finds a row and so
    # *differs* from the baseline, while FALSE matches it. Measured on DVWA's
    # blind page: id= renders "User ID is MISSING", id=1 renders "User ID
    # exists". Seed a value that returns something, exactly as a human tester
    # would type one in, and the asymmetry points the right way again.
    if not value:
        value = SEED_VALUE

    try:
        baseline = _send(session, url, method, param, value, siblings)
        baseline_body = baseline.text
        baseline_times = [baseline.elapsed_seconds]

        # Ask the page the same question twice. If it answers identically we can
        # compare content later instead of sizes, which is the difference
        # between catching DVWA's blind page and walking past it.
        baseline2 = _send(session, url, method, param, value, siblings)
        baseline_times.append(baseline2.elapsed_seconds)
        strict = V.stable_baseline(baseline_body, baseline2.text)

        # -- stage 1: error-based ------------------------------------------
        for p in payloads.select(context, 1):
            body = _send(session, url, method, param, value + p.value, siblings).text
            hit, why = V.judge_error_based(body, payloads.ERROR_SIGNATURES)
            if hit:
                return _result(True, "error-based", why, p.value, 1, used())

        # -- stage 2: boolean-blind ----------------------------------------
        for true_p, false_p in payloads.select(context, 2):
            t = _send(session, url, method, param, value + true_p, siblings).text
            f = _send(session, url, method, param, value + false_p, siblings).text
            hit, why = V.judge_boolean_blind(baseline_body, t, f, strict)
            if hit:
                return _result(True, "boolean-blind", why,
                               "%s  vs  %s" % (true_p, false_p), 2, used())

        # -- stage 3: time-blind -------------------------------------------
        # Serialised, and the baseline is re-measured, because the whole
        # technique is a comparison against how fast this page normally is.
        for p in payloads.select(context, 3):
            first = _send(session, url, method, param, value + p.value, siblings)
            if first.elapsed_seconds < min(baseline_times) + V.DELAY_THRESHOLD:
                continue                      # no point paying for a reproduction
            second = _send(session, url, method, param, value + p.value, siblings)
            hit, why = V.judge_time_blind(baseline_times, first.elapsed_seconds,
                                          second.elapsed_seconds)
            if hit:
                return _result(True, "time-blind", why, p.value, 3, used())

        return _result(False, "none", "", "", 3, used())

    except Exception as exc:
        # Never invent a verdict out of a failure. A point we could not reach is
        # undetermined, and the report has to say so instead of reading silence
        # as safety.
        return _result(False, "none", "", "", 0, used(),
                       error="%s: %s" % (type(exc).__name__, exc))
