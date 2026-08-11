"""The only place a verdict is decided.

OWNER: tprud9412.

Every rule here is written out in skills/sqli-payloads/references/*.md, and the
two must stay in step -- during the demo we open the document and this file side
by side to show why we called something vulnerable. If you change a threshold
here, change the sentence there in the same commit.

No HTTP and no model calls. Responses come in as strings and numbers, verdicts
come out. That is what makes this testable without a target.
"""

from __future__ import annotations

import re

# A response has to be this much longer or shorter before we call it different.
# Timestamps and tokens move a page by a few bytes on every render, so exact
# equality would call every page dynamic and every parameter undetermined.
SAME_TOLERANCE = 0.02

# A payload sleeps for SLEEP_SECONDS; we require most of it to show up. The gap
# is deliberate slack for one internet round trip.
DELAY_THRESHOLD = 4.0


def normalise(body: str) -> str:
    """Strip the parts of a page that change on every render.

    Without this, a CSRF token alone makes two identical pages compare unequal.
    """
    out = re.sub(r"[0-9a-f]{32}", "TOKEN", body or "")
    out = re.sub(r"\d{2}:\d{2}:\d{2}", "TIME", out)
    return " ".join(out.split())


def looks_same(a: str, b: str, strict: bool = False) -> bool:
    """strict compares content exactly; otherwise allow a small size drift.

    Which one to use is not a preference, it is measured -- see stable_baseline.
    """
    if not a or not b:
        return a == b
    if strict:
        return normalise(a) == normalise(b)
    return abs(len(a) - len(b)) / max(len(a), len(b)) < SAME_TOLERANCE


def stable_baseline(first: str, second: str) -> bool:
    """Does this page render identically twice in a row?

    If it does, we can compare content exactly, and a six-byte difference is
    signal. DVWA's blind page answers "User ID exists in the database." or
    "...is MISSING from the database." -- a 6-byte swing inside 4.7 KB, which is
    0.13% and vanishes under any percentage tolerance. Measuring stability first
    is what lets us read a difference that small without calling every dynamic
    page vulnerable.
    """
    return normalise(first) == normalise(second)


def judge_error_based(body: str, signatures) -> tuple[bool, str]:
    """Confirmed when the response carries a fingerprint the DB engine produced.

    A 500, an empty page, or "Something went wrong" is not evidence. Those are
    the application talking. We need the database talking.
    """
    low = (body or "").lower()
    for sig in signatures:
        if sig.lower() in low:
            i = low.find(sig.lower())
            excerpt = " ".join((body[max(0, i - 40):i + 180]).split())
            return True, "DB error fingerprint %r in response: ...%s..." % (sig, excerpt)
    return False, ""


def judge_boolean_blind(baseline: str, true_body: str, false_body: str,
                        strict: bool = False) -> tuple[bool, str]:
    """Confirmed only on the asymmetry: TRUE matches the baseline, FALSE does not.

    "The two payloads gave different responses" is not enough. An invalid id also
    gives a different response. What separates injection from ordinary behaviour
    is that the TRUE condition brings the page *back* to the baseline.

    strict is set by the caller after measuring whether the page renders
    identically twice. On a stable page we compare content, which is what lets a
    six-byte difference count; on a page that moves by itself we fall back to a
    size tolerance and usually end up undetermined, which is the honest answer.
    """
    t_same = looks_same(baseline, true_body, strict)
    f_same = looks_same(baseline, false_body, strict)
    how = "content" if strict else "size within %.0f%%" % (SAME_TOLERANCE * 100)
    sizes = "baseline %d bytes / TRUE %d / FALSE %d, compared by %s" % (
        len(baseline or ""), len(true_body or ""), len(false_body or ""), how)

    if t_same and not f_same:
        return True, "asymmetry confirmed - %s (TRUE matches baseline, FALSE differs)" % sizes
    if t_same and f_same:
        return False, "no reaction - %s (input never reaches the query)" % sizes
    return False, "undetermined - %s (TRUE already differs; page may be dynamic)" % sizes


def judge_time_blind(baseline_times, first: float, second: float) -> tuple[bool, str]:
    """Confirmed when the delay clears the threshold twice in a row.

    One slow response is network weather. Requiring a reproduction is what keeps
    a congested link from being reported as a database.
    """
    if not baseline_times:
        return False, "no baseline measured"
    base = sum(baseline_times) / len(baseline_times)
    spread = max(baseline_times) - min(baseline_times)
    shape = "baseline avg %.2fs (spread %.2fs), 1st %.2fs, 2nd %.2fs" % (
        base, spread, first, second)

    if spread >= DELAY_THRESHOLD:
        return False, "unusable - %s (baseline is too unstable to read a delay)" % shape
    if first >= base + DELAY_THRESHOLD and second >= base + DELAY_THRESHOLD:
        return True, "delay reproduced twice - %s" % shape
    if first >= base + DELAY_THRESHOLD:
        return False, "not reproduced - %s (one-off delay, not evidence)" % shape
    return False, "no delay - %s" % shape
