# -*- coding: utf-8 -*-
"""
Ground truth -- DVWA / CWE-89

IMPORTANT: instructor's remark (section 23)
   "This is not something the LLM judges. The LLM cannot get this wrong.
    This is ground truth. It is written in advance, and it is static data."

  -> This file is **written by hand**. It is not LLM-generated.
  -> It is finished **before** the pipeline is.

IMPORTANT: always mix all four kinds
   vulnerable (obvious) / vulnerable (blind) / not vulnerable / trap
   Without non-vulnerable samples, a pipeline that answers "everything is
   vulnerable" gets a perfect score.

WARNING: entries marked VERIFY must be **confirmed by eye on the actually
   deployed instance** before they are finalized and the mark is removed.
   DVWA behaves differently depending on version and security level.
   The baseline assumes security level is set to **low**.
"""

from dataclasses import dataclass, field
from typing import Literal, Optional

Technique = Literal["error-based", "boolean-blind", "time-blind", "none"]


@dataclass(frozen=True)
class Expected:
    url: str                       # path after base_url
    method: str                    # GET | POST
    param: str                     # the answer applies to this one parameter
    is_vulnerable: bool            # <- the answer
    technique: Technique           # if vulnerable, which technique confirms it
    cwe_id: str = "CWE-89"
    severity: str = "high"
    requires_auth: bool = True     # most of DVWA requires login
    note: str = ""
    verify: bool = False           # True means not yet confirmed against the real target


# ---------------------------------------------------------------------------
# (1) Vulnerable -- obvious (error-based). Tier 1
# ---------------------------------------------------------------------------
VULNERABLE_OBVIOUS = [
    Expected(
        url="/vulnerabilities/sqli/", method="GET", param="id",
        is_vulnerable=True, technique="error-based",
        note="DVWA's canonical SQLi page. At low level a single quote raises a MariaDB "
             "error. Needs Submit=Submit alongside it or the query never executes",
    ),
    Expected(
        url="/vulnerabilities/brute/", method="GET", param="username",
        is_vulnerable=True, technique="error-based",
        note="The brute-force page builds WHERE user='$user' AND password='$pass' at "
             "low level and prints the DB error. Confirmed on our instance that the "
             "form is GET with username, password and Login. It is a login form, so a "
             "scanner that only looks at pages named 'sqli' walks straight past it",
    ),
]

# ---------------------------------------------------------------------------
# (2) Vulnerable -- blind. Tier 2
# ---------------------------------------------------------------------------
VULNERABLE_BLIND = [
    Expected(
        url="/vulnerabilities/sqli_blind/", method="GET", param="id",
        is_vulnerable=True, technique="boolean-blind",
        note="No errors are printed. Judged only by the difference between true/false responses",
    ),
]

# ---------------------------------------------------------------------------
# (3) Not vulnerable -- for measuring the false positive rate.
#     IMPORTANT: without these the evaluation is meaningless
# ---------------------------------------------------------------------------
NOT_VULNERABLE = [
    Expected(
        url="/login.php", method="POST", param="username",
        is_vulnerable=False, technique="none", severity="low",
        requires_auth=False,
        note="UNVERIFIED. DVWA's own login page, not part of the vulnerable-by-design "
             "exercise surface, so we labelled it clean. That is an assumption, not a "
             "finding: whether login.php parameterises this query varies by DVWA "
             "version, and ours is PHP 8.5. Confirm it on the deployed instance before "
             "quoting any precision number - if it turns out injectable, this label is "
             "manufacturing a false positive out of a correct detection",
        verify=True,
    ),
    Expected(
        url="/security.php", method="POST", param="security",
        is_vulnerable=False, technique="none", severity="low",
        note="Security level selector. The value never reaches the DB",
        verify=True,
    ),
]

# ---------------------------------------------------------------------------
# (4) Traps -- looks like SQL but never touches the DB.
#     IMPORTANT: tests whether judgement is based on appearance alone
#     Instructor, section 21: "insert dead code / unreachable code to
#     determine the quality of the system"
# ---------------------------------------------------------------------------
TRAPS = [
    Expected(
        url="/vulnerabilities/sqli/", method="GET", param="Submit",
        is_vulnerable=False, technique="none", severity="low",
        note="Button value. It is named like a form field but never enters the query. "
             "Firing payloads at it means the prioritization is wrong",
    ),
    Expected(
        url="/vulnerabilities/exec/", method="POST", param="ip",
        is_vulnerable=False, technique="none", severity="low",
        note="IMPORTANT: command injection works here, but this is not SQL injection. "
             "Tests whether 'looks vulnerable' is distinguished from 'is CWE-89'",
    ),
]

ALL: list[Expected] = (
    VULNERABLE_OBVIOUS + VULNERABLE_BLIND + NOT_VULNERABLE + TRAPS
)


# ---------------------------------------------------------------------------
# Scoring -- deterministic. No LLM involved.
# ---------------------------------------------------------------------------
@dataclass
class Score:
    tp: int = 0          # vulnerable, called vulnerable
    fp: int = 0          # not vulnerable, called vulnerable   <- false positive
    fn: int = 0          # vulnerable, missed                  <- false negative
    tn: int = 0          # not vulnerable, called not vulnerable
    undetermined: int = 0  # never actually tested  <- NOT a clean negative
    technique_hit: int = 0
    missed: list = field(default_factory=list)
    false_alarms: list = field(default_factory=list)
    not_tested: list = field(default_factory=list)

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def report(self) -> str:
        lines = [
            f"  detection  TP={self.tp}  FN={self.fn}   (recall {self.recall:.2f})",
            f"  precision  FP={self.fp}  TN={self.tn}   (precision {self.precision:.2f})",
            f"  F1         {self.f1:.2f}",
            f"  technique also correct  {self.technique_hit}/{self.tp}",
        ]
        if self.undetermined:
            lines.append(
                f"  NOT TESTED {self.undetermined}"
                f"  (excluded from the scores above, never counted as a pass)")
        for label, items in (("MISSED", self.missed),
                             ("INVENTED", self.false_alarms),
                             ("NOT REACHED", self.not_tested)):
            lines += [f"    {label}: {it}" for it in items]
        return "\n".join(lines) + "\n"


def _path_of(url: str) -> str:
    """Reduce a finding's url to the path we key on.

    The pipeline reports a full URL ("https://host/vulnerabilities/sqli/") while
    the labels above are paths ("/vulnerabilities/sqli/"). Comparing those two
    strings raw matches nothing, every case scores as a miss, and the report
    reads like a total detection failure instead of a broken join.
    """
    if "://" in url:
        url = url.split("://", 1)[1]
        url = url[url.find("/"):] if "/" in url else "/"
    url = url.split("?", 1)[0].split("#", 1)[0]
    return url.rstrip("/") or "/"


def grade(findings: list[dict]) -> Score:
    """
    findings: pipeline output.
        [{"url":..., "method":..., "param":..., "vulnerable":bool,
          "technique":str, "error":str|None}]

    A finding with a non-null "error" was never actually tested. It is scored as
    undetermined, not as a clean negative -- otherwise a pipeline that fails to
    reach a page collects the same credit as one that cleared it.
    """
    got = {
        (_path_of(f["url"]), f.get("method", "GET").upper(), f["param"]): f
        for f in findings
    }
    s = Score()
    for exp in ALL:
        key = (_path_of(exp.url), exp.method.upper(), exp.param)
        f = got.get(key)
        said_vuln = bool(f and f.get("vulnerable"))

        if f is not None and f.get("error"):
            s.undetermined += 1
            s.not_tested.append(f"{exp.url}?{exp.param}  ({f['error']})")
        elif f is None and not exp.is_vulnerable:
            # Never reported at all. Triage is *supposed* to drop low-value points,
            # so this is not a failure -- but it is not a correct rejection either.
            # Counting it as a true negative would pay a pipeline for the pages it
            # never looked at, and the cheapest way to a perfect precision score
            # would be to test nothing.
            s.undetermined += 1
            s.not_tested.append(f"{exp.url}?{exp.param}  (not selected by triage)")
        elif exp.is_vulnerable and said_vuln:
            s.tp += 1
            if f.get("technique") == exp.technique:
                s.technique_hit += 1
        elif exp.is_vulnerable and not said_vuln:
            s.fn += 1
            s.missed.append(f"{exp.url}?{exp.param}")
        elif not exp.is_vulnerable and said_vuln:
            s.fp += 1
            s.false_alarms.append(f"{exp.url}?{exp.param}")
        else:
            s.tn += 1

    # Anything the report claims that we never labelled. These are the dangerous
    # ones: an invented finding is worse than a missed one, and dropping it here
    # would hide it from the score entirely.
    labelled = {(_path_of(e.url), e.method.upper(), e.param) for e in ALL}
    for k, f in got.items():
        if k not in labelled and f.get("vulnerable"):
            s.fp += 1
            s.false_alarms.append(f"UNLABELLED {k[1]} {k[0]}?{k[2]}")
    return s


if __name__ == "__main__":
    print(f"ground truth entries: {len(ALL)}")
    print(f"  vulnerable(obvious) {len(VULNERABLE_OBVIOUS)} / vulnerable(blind) {len(VULNERABLE_BLIND)}"
          f" / not vulnerable {len(NOT_VULNERABLE)} / traps {len(TRAPS)}")
    todo = [e for e in ALL if e.verify]
    if todo:
        # Use no non-ASCII symbols so this does not crash on a Windows cp949 console
        # (the problem we hit yesterday)
        print(f"\n[NEEDS VERIFICATION] {len(todo)} entries - confirm by eye on the deployed instance")
        for e in todo:
            print(f"   - {e.method} {e.url}  param={e.param}   ({e.note})")
