"""Run the pipeline, score it against ground truth, and prove it repeats.

OWNER: tprud9412.

    python eval/run_eval.py --target URL                  score one stub run
    python eval/run_eval.py --target URL --runs 3         score three, then diff them
    python eval/run_eval.py --target URL --llm --runs 3   score the deep agent

Consistency is a graded requirement and the easiest one to fake, so it is
measured here rather than asserted in a slide: the same target is run N times
and the confirmed sets are compared. Identical sets is the claim; anything else
prints what moved.

**--llm is what makes the score mean anything.** Without it stages 2 and 4 are
deterministic Python, so a perfect score measures a rule table, not the agent we
are presenting -- and the consistency number is trivially perfect because no
model was involved. The path that was measured is recorded in the output as
`mode`, so a number can never be quoted without saying which run produced it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import config, pipeline           # noqa: E402
from eval.ground_truth import ALL, grade     # noqa: E402

ARTIFACTS = Path(__file__).resolve().parent.parent / "artifacts"


def confirmed_set(summary):
    return {(f["url"], f["method"], f["param"], f["technique"])
            for f in summary["findings"] if f["vulnerable"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=config.DEFAULT_TARGET)
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--llm", action="store_true",
                    help="score the deep agent instead of the Python stubs")
    ap.add_argument("--mcp", action="store_true",
                    help="reach the tools through mcp_server.py over stdio "
                         "instead of importing them in process")
    args = ap.parse_args()

    # Both flags go into `mode`, because "which score is this" has two axes and
    # a demo that shows one number needs to say which run produced it.
    mode = "%s+%s" % ("deep-agent" if args.llm else "stub",
                      "mcp" if args.mcp else "in-process")
    summaries = []
    for i in range(args.runs):
        print("\n===== run %d/%d (%s) =====" % (i + 1, args.runs, mode))
        summaries.append(pipeline.run(args.target, use_llm=args.llm,
                                      use_mcp=args.mcp))

    print("\n===== score (run 1 of %d, %d labels, %s) ====="
          % (args.runs, len(ALL), mode))
    score = grade(summaries[0]["findings"])
    print(score.report())

    sets = [confirmed_set(s) for s in summaries]
    identical = all(s == sets[0] for s in sets)
    print("===== consistency over %d runs =====" % args.runs)
    print("  confirmed sets identical: %s" % ("yes" if identical else "NO"))
    for i, s in enumerate(sets, 1):
        print("    run %d: %d confirmed, %d requests"
              % (i, len(s), summaries[i - 1]["requests_used"]))
    if not identical:
        union = set().union(*sets)
        for item in sorted(union):
            missing = [i + 1 for i, s in enumerate(sets) if item not in s]
            if missing:
                print("    UNSTABLE %s  absent from run(s) %s" % (item, missing))

    # `mode` first, and never omitted: a score with no path attached is the one
    # way this file can mislead. "stub" means no model ran, so both the F1 and
    # the consistency line describe a rule table.
    out = {"target": args.target, "mode": mode, "runs": args.runs,
           "labels": len(ALL),
           "tp": score.tp, "fp": score.fp, "fn": score.fn, "tn": score.tn,
           "undetermined": score.undetermined,
           "precision": round(score.precision, 3), "recall": round(score.recall, 3),
           "f1": round(score.f1, 3),
           "technique_hit": score.technique_hit,
           "missed": score.missed, "invented": score.false_alarms,
           "not_tested": score.not_tested,
           "consistency": {"identical": identical,
                           "per_run_confirmed": [len(s) for s in sets],
                           "per_run_requests": [s["requests_used"] for s in summaries]}}
    ARTIFACTS.mkdir(exist_ok=True)
    (ARTIFACTS / "06_evaluation.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("\n  wrote artifacts/06_evaluation.json")
    return 0 if identical else 1


if __name__ == "__main__":
    raise SystemExit(main())
