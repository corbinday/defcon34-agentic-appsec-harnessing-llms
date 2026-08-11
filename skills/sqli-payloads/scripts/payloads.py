"""Loader and group selector for the payload corpus.

The corpus itself is data, in ../data/*.json. This file holds no payload strings
at all -- it loads them and decides which group goes out. That split is the point:
adding PostgreSQL support is an entry in a JSON file, and this module does not
change. Anyone on the team can read the corpus without reading Python.

**The LLM picks the group. The code expands the group.**

    LLM emits    (context, dbms, depth)
    select()     -> an exact, ordered list of payloads

Same triple in, same list out, always. That is what lets the corpus grow to any
size without touching requirement 6: consistency is a property of the mapping,
not of the corpus being small.

Ordering rule: the judged dialect goes first, then the engine-agnostic entries,
then the rest. The likely hit lands early, the run still stops at the first
confirmation, and nothing is silently dropped just because the guess was wrong.
That matters -- DVWA at low quotes a numeric-looking id, so a run that trusted
"looks numeric" and stopped there would miss the blind page outright.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

DATA = Path(__file__).resolve().parent.parent / "data"

Context = Literal["numeric", "string", "double-quoted", "paren", "unknown"]
Dbms = Literal["mysql", "postgres", "mssql", "oracle", "sqlite", "unknown"]
Depth = Literal["quick", "standard", "deep"]
Technique = Literal["error-based", "boolean-blind", "time-blind"]

# How far each depth is allowed to go. The LLM spends "deep" on the parameters
# most likely to reach a database, not on all of them.
DEPTH_STAGES = {"quick": (1,), "standard": (1, 2, 3), "deep": (1, 2, 3)}


@dataclass(frozen=True)
class Payload:
    value: str
    technique: Technique
    context: str
    dbms: str = "any"
    note: str = ""


def _load(name):
    with open(DATA / name, encoding="utf-8") as fh:
        return json.load(fh)


_PAYLOADS = _load("payloads.json")
_SIGNATURES = _load("error_signatures.json")["signatures"]

# A flat list of strings, so callers written against the old module keep working.
# verdict.judge_error_based takes exactly this.
ERROR_SIGNATURES = [s["match"] for s in _SIGNATURES]

ERROR_BASED = [Payload(p["value"], "error-based", p.get("context", "any"),
                       p.get("dbms", "any"), p.get("note", ""))
               for p in _PAYLOADS["error_suffix"]]

CONTEXT_PROOF = _PAYLOADS.get("context_proof", [])


def identify_dbms(body: str) -> str | None:
    """Which engine produced this error, if any.

    Free information: stage 1 already fetched the response, so a hit here can
    narrow stages 2 and 3 from "every dialect" to one without spending a request.
    """
    low = (body or "").lower()
    for sig in _SIGNATURES:
        if sig["match"].lower() in low and sig["dbms"] != "any":
            return sig["dbms"]
    return None


def _rank(entry_dbms: str, judged: str) -> int:
    if entry_dbms == judged:
        return 0
    if entry_dbms == "any":
        return 1
    return 2


def _ordered(entries, dbms, context, deep):
    """Judged labels decide ORDER. Only depth decides membership.

    A wrong guess costs a few extra requests. A wrong guess that *removed*
    payloads would cost the finding, so membership is never narrowed by a label
    the model produced -- only by how hard we said we were willing to push.
    """
    ranked = sorted(
        entries,
        key=lambda e: (_rank(e.get("dbms", "any"), dbms),
                       0 if e.get("context", "any") in (context, "any") else 1))
    if deep:
        return ranked
    trimmed = [e for e in ranked if _rank(e.get("dbms", "any"), dbms) <= 1]
    return trimmed or ranked


def stages_for(depth: Depth = "standard"):
    """Which stages this depth is allowed to run."""
    return DEPTH_STAGES.get(depth, DEPTH_STAGES["standard"])


def select(context: Context, stage: int, dbms: Dbms = "unknown",
           depth: Depth = "standard") -> list:
    """The fixed group for one (context, dbms, depth) triple at one stage.

    stage 1: error-based    cheap, always first
    stage 2: boolean-blind  pairs, when stage 1 stayed silent
    stage 3: time-blind     last, five seconds a payload

    Returns Payload objects for stages 1 and 3, and (true, false) string pairs
    for stage 2 -- a boolean test is meaningless unless both arms are sent.
    """
    if stage not in stages_for(depth):
        return []
    deep = depth == "deep"

    if stage == 1:
        # Syntax breakers are dialect-independent, so the whole group always goes
        # out. This is the cheapest stage and it finds most of everything.
        return list(ERROR_BASED)

    if stage == 2:
        pairs = _ordered(_PAYLOADS["boolean_pairs"], dbms, context, deep)
        return [(p["true"], p["false"]) for p in pairs]

    if stage == 3:
        rows = _ordered(_PAYLOADS["time"], dbms, context, deep)
        if not deep:
            # Every entry here costs five seconds, and it is sent twice to
            # confirm the delay reproduces. Firing all ten dialects at an
            # unidentified engine is a minute per parameter for one finding at
            # most. Below "deep" we take the two best-ranked and stop; "deep" is
            # the label that says the caller accepted that bill.
            rows = rows[:2]
        return [Payload(r["value"], "time-blind", r.get("context", "any"),
                        r.get("dbms", "any"), r.get("note", "")) for r in rows]

    return []


def has_sql_error(body: str) -> str | None:
    """The fingerprint present in this response body, if any."""
    low = (body or "").lower()
    for sig in ERROR_SIGNATURES:
        if sig.lower() in low:
            return sig
    return None


def corpus_summary() -> dict:
    dialects = sorted({s["dbms"] for s in _SIGNATURES} |
                      {p.get("dbms", "any") for p in _PAYLOADS["time"]})
    return {"error_signatures": len(ERROR_SIGNATURES),
            "error_suffixes": len(ERROR_BASED),
            "boolean_pairs": len(_PAYLOADS["boolean_pairs"]),
            "time_payloads": len(_PAYLOADS["time"]),
            "context_proofs": len(CONTEXT_PROOF),
            "dialects": dialects}


if __name__ == "__main__":
    s = corpus_summary()
    print("corpus: %d error signatures, %d suffixes, %d boolean pairs, %d time payloads"
          % (s["error_signatures"], s["error_suffixes"],
             s["boolean_pairs"], s["time_payloads"]))
    print("dialects: %s" % ", ".join(s["dialects"]))
    print()
    for depth in ("quick", "standard", "deep"):
        for dbms in ("mysql", "postgres", "unknown"):
            counts = [len(select("string", st, dbms, depth)) for st in (1, 2, 3)]
            print("  depth=%-8s dbms=%-8s stages 1/2/3 -> %d / %d / %d"
                  % (depth, dbms, counts[0], counts[1], counts[2]))
    print()
    print("same triple twice gives the same list:",
          select("string", 2, "mysql", "deep") == select("string", 2, "mysql", "deep"))
