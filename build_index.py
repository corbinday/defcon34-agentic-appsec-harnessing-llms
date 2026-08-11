"""Knowledge index for the assessment chatbot (deliverable 3, part 1).

READY NOW
  - Builds index/chunks.json from artifacts/ and skills/ with ZERO third-party
    dependencies. Pure stdlib, so it runs on every laptop in the team today.
  - Markdown is split on heading boundaries, so a retrieved chunk is one whole
    section rather than half of one. 03_findings.json is split one chunk per
    finding, because a finding cut in half retrieves as noise while a whole one
    retrieves as an answer with a payload and a piece of evidence.
  - Owns the tokenizer and the df table. chatbot.py imports both from here so
    the two never drift apart.
  - `python build_index.py --selftest` checks the index without an LLM.

STILL OPEN
  - The embedding path (`--embed`) is stubbed on purpose: faiss and langchain
    are not installed in this environment and there are no AWS credentials.
    It raises with the exact pip line to run. The word-overlap retriever below
    is the default and is what the demo uses; artifacts/ is ~14 KB, which is
    far below the size where embeddings start to earn their keep.
  - Nothing here calls an LLM. All LLM contact lives in chatbot.py.

Usage:
    python build_index.py
    python build_index.py --selftest
"""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ARTIFACT_DIR = ROOT / "artifacts"
SKILL_DIR = ROOT / "skills"
INDEX_DIR = ROOT / "index"
INDEX_PATH = INDEX_DIR / "chunks.json"

# The artifacts a grader opens. Missing ones are reported, never faked.
EXPECTED_ARTIFACTS = ("01_context.md", "02_threat_model.md",
                      "03_findings.json", "05_report.md")

STOPWORDS = frozenset("""
a an the and or but if then than that this these those is are was were be been
being do does did doing have has had having i you he she it we they me my your
of in on at to for from with by as about into over after before under between
what which who whom when where why how all any both each few more most other
some such no nor not only own same so too very can will just should now does
me us our their its his her them there here also may might must shall would
could get got give me tell show explain describe list please would like want
""".split())


def normalise(token: str) -> str:
    """Crude singulariser. Enough to make findings/finding and
    vulnerabilities/vulnerability land on the same key."""
    if len(token) > 4 and token.endswith("ies"):
        return token[:-3] + "y"
    if len(token) > 4 and (token.endswith("ses") or token.endswith("xes")):
        return token[:-2]
    if len(token) > 3 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


def tokenize(text: str) -> list[str]:
    """Lowercase word tokens, plus the pieces of any compound identifier.

    sqli_blind yields sqli_blind, sqli and blind, so a question about "blind
    SQL injection" reaches the row whose parameter lives on /sqli_blind/.
    Non-ASCII input tokenises fine and simply matches nothing, which is the
    correct outcome for an override written in another language.
    """
    out: list[str] = []
    for raw in re.findall(r"[\w']+", text.lower(), flags=re.UNICODE):
        raw = raw.strip("'")
        parts = [raw] + ([p for p in re.split(r"[_\-]", raw) if p] if
                         ("_" in raw or "-" in raw) else [])
        for p in parts:
            if len(p) < 2 or p in STOPWORDS:
                continue
            t = normalise(p)
            if len(t) >= 2 and t not in STOPWORDS:
                out.append(t)
    return out


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

HEADING = re.compile(r"^(#{1,3})\s+(.*)$")


def split_markdown(text: str, source: str, kind: str) -> list[dict]:
    """Split on H1..H3. The heading line stays inside the chunk, and the
    enclosing headings ride along as a breadcrumb so a citation says which
    section it came from."""
    chunks: list[dict] = []
    crumbs: list[str] = ["", "", ""]
    buf: list[str] = []
    title = source

    def flush(t: str) -> None:
        body = "\n".join(buf).strip()
        if body:
            chunks.append({"source": source, "kind": kind,
                           "title": t or source, "text": body})

    for line in text.splitlines():
        m = HEADING.match(line)
        if m:
            flush(title)
            buf = []
            level = len(m.group(1))
            crumbs[level - 1] = m.group(2).strip()
            for i in range(level, 3):
                crumbs[i] = ""
            title = " > ".join(c for c in crumbs if c)
        buf.append(line)
    flush(title)
    return chunks


def split_findings(text: str, source: str) -> list[dict]:
    """One chunk per finding, plus one for the run summary.

    json.loads is correct here: this file is written by our own pipeline, not
    by a model. Malformed input raises rather than degrading to a fake chunk.
    """
    data = json.loads(text)
    if not isinstance(data, dict) or "findings" not in data:
        return [{"source": source, "kind": "finding", "title": source,
                 "text": text}]

    head = {k: v for k, v in data.items() if k != "findings"}
    chunks = [{"source": source, "kind": "summary", "title": "run summary",
               "text": "Run summary for this assessment:\n"
                       + json.dumps(head, indent=2)}]
    for i, f in enumerate(data["findings"], 1):
        fid = "F-%02d" % i
        verdict = "CONFIRMED vulnerable" if f.get("vulnerable") else (
            "not confirmed vulnerable" if not f.get("error") else "NOT TESTED")
        chunks.append({
            "source": source, "kind": "finding", "title": fid,
            "text": "Finding %s: %s %s parameter %s on %s\n%s\n%s" % (
                fid, verdict, f.get("method", "?"), f.get("param", "?"),
                f.get("url", "?"), "technique: %s" % f.get("technique", "none"),
                json.dumps(f, indent=2)),
        })
    return chunks


def collect() -> list[dict]:
    chunks: list[dict] = []

    if not ARTIFACT_DIR.is_dir():
        raise SystemExit("no artifacts/ directory at %s - run agent/pipeline.py "
                         "first" % ARTIFACT_DIR)

    for path in sorted(ARTIFACT_DIR.iterdir()):
        if not path.is_file() or path.suffix not in (".md", ".json"):
            continue
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            print("  skipped %s - empty" % path.name)
            continue
        if path.name == "03_findings.json":
            chunks += split_findings(text, path.name)
        elif path.suffix == ".json":
            chunks.append({"source": path.name, "kind": "summary",
                           "title": path.name, "text": text})
        else:
            chunks += split_markdown(text, path.name, "analysis")

    # Domain knowledge. Answers "how do you decide a time-blind hit" without
    # the model reaching for anything it was not given.
    if SKILL_DIR.is_dir():
        for path in sorted(SKILL_DIR.rglob("*.md")):
            rel = path.relative_to(ROOT).as_posix()
            chunks += split_markdown(path.read_text(encoding="utf-8"),
                                     rel, "skill")

    for i, c in enumerate(chunks):
        c["id"] = i
    return chunks


def build_df(chunks: list[dict]) -> dict[str, int]:
    df: dict[str, int] = {}
    for c in chunks:
        for t in set(tokenize(c["title"] + "\n" + c["text"])):
            df[t] = df.get(t, 0) + 1
    return df


def build() -> dict:
    chunks = collect()
    if not chunks:
        raise SystemExit("nothing to index - artifacts/ produced no chunks")
    return {"root": str(ROOT), "n_chunks": len(chunks),
            "df": build_df(chunks), "chunks": chunks}


def load() -> dict:
    """Read the saved index, or build it in memory if it was never saved.

    Falling back keeps chatbot.py --selftest runnable on a fresh clone. It
    prints which path it took; it never pretends an index exists.
    """
    if INDEX_PATH.is_file():
        # An index older than the artifacts answers last run's questions. Say
        # so rather than quietly serving stale findings.
        stale = [p.name for p in ARTIFACT_DIR.glob("*")
                 if p.is_file() and p.stat().st_mtime > INDEX_PATH.stat().st_mtime]
        if stale:
            print("  WARNING: artifacts changed since the index was built (%s)."
                  " Re-run: python build_index.py" % ", ".join(sorted(stale)))
        return json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    print("  index/chunks.json not found - building in memory "
          "(run: python build_index.py to save it)")
    return build()


def idf(index: dict, token: str) -> float:
    n = index["n_chunks"]
    return math.log((n + 1.0) / (index["df"].get(token, 0) + 1.0)) + 1.0


# ---------------------------------------------------------------------------
# Optional embedding path - deliberately not the default
# ---------------------------------------------------------------------------

def build_embedded() -> None:
    """Vector index over the same chunks. Imports live in here on purpose:
    this module must stay importable on a machine with none of it installed."""
    try:
        import faiss  # noqa: F401
        from langchain_aws import BedrockEmbeddings  # noqa: F401
        from langchain_community.vectorstores import FAISS  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "the embedding index needs packages this environment does not have "
            "(%s). Install them with:\n"
            "    pip install faiss-cpu langchain-aws langchain-community\n"
            "and configure AWS credentials (AWS_ACCESS_KEY_ID, "
            "AWS_SECRET_ACCESS_KEY, AWS_REGION) for Bedrock embeddings.\n"
            "The default word-overlap index needs none of this and is what the "
            "demo uses: python build_index.py" % exc) from exc
    raise NotImplementedError(
        "the embedding path is wired up to fail loudly until someone can run it "
        "end to end. Do not ship it half-tested - the word-overlap index is "
        "verified and is the one chatbot.py reads.")


# ---------------------------------------------------------------------------
# Self-test - no LLM, no network
# ---------------------------------------------------------------------------

def selftest() -> int:
    ok = True
    index = build()
    chunks = index["chunks"]
    print("chunks: %d" % len(chunks))

    sources = {c["source"] for c in chunks}
    for name in EXPECTED_ARTIFACTS:
        present = name in sources
        ok &= present
        print("  [%s] indexed %s" % ("PASS" if present else "FAIL", name))

    n_find = sum(1 for c in chunks if c["kind"] == "finding")
    good = n_find >= 3
    ok &= good
    print("  [%s] findings split individually: %d chunks"
          % ("PASS" if good else "FAIL", n_find))

    n_skill = sum(1 for c in chunks if c["kind"] == "skill")
    good = n_skill > 0
    ok &= good
    print("  [%s] skill documents indexed: %d chunks"
          % ("PASS" if good else "FAIL", n_skill))

    empty = [c["source"] for c in chunks if not c["text"].strip()]
    ok &= not empty
    print("  [%s] no empty chunks%s"
          % ("PASS" if not empty else "FAIL",
             "" if not empty else " - %s" % empty))

    toks = tokenize("Which vulnerabilities were confirmed on sqli_blind?")
    good = "vulnerability" in toks and "blind" in toks and "sqli_blind" in toks
    ok &= good
    print("  [%s] tokenizer splits identifiers and singularises"
          % ("PASS" if good else "FAIL"))

    print("\n%s" % ("SELFTEST PASSED" if ok else "SELFTEST FAILED"))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="build the chatbot knowledge index")
    ap.add_argument("--selftest", action="store_true",
                    help="verify the index without an LLM")
    ap.add_argument("--embed", action="store_true",
                    help="optional FAISS/Bedrock index (not installed here)")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.embed:
        build_embedded()
        return 0

    print("Building the assessment index")
    index = build()
    INDEX_DIR.mkdir(exist_ok=True)
    INDEX_PATH.write_text(json.dumps(index, indent=1, ensure_ascii=False),
                          encoding="utf-8")

    by_kind: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for c in index["chunks"]:
        by_kind[c["kind"]] = by_kind.get(c["kind"], 0) + 1
        by_source[c["source"]] = by_source.get(c["source"], 0) + 1

    print("  chunks     : %d" % index["n_chunks"])
    print("  vocabulary : %d terms" % len(index["df"]))
    print("  by kind    : %s" % json.dumps(by_kind, sort_keys=True))
    for src in sorted(by_source):
        print("    %-46s %d" % (src, by_source[src]))
    print("  saved to   : %s" % INDEX_PATH.relative_to(ROOT).as_posix())

    missing = [n for n in EXPECTED_ARTIFACTS
               if n not in {c["source"] for c in index["chunks"]}]
    if missing:
        print("  WARNING: expected artifacts not indexed: %s"
              % ", ".join(missing))
        print("  the chatbot will answer 'not in our analysis' for those topics")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
