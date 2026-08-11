# AGENTS.md

**Blueprint for the AI coding tools we each drive (Claude Code, Cursor) and for us.**

Point your assistant at this file, then at *your* section under
[6. Work orders](#6-work-orders). Do not make it read the whole repo first.

**If the code and this file disagree, fix this file first, then the code.**

---

## 0. Read this first

**Demo is at 16:15. Everything below is scoped to fit before then.**

We are not designing a product. We are shipping **five artifacts** a grader can
open, plus **one deep agent** that produces them. Anything that does not end in a
file we can show at 16:15 is out of scope today.

### What is already in this repo (verified — do not re-create these)

```
skills/endpoint-discovery/SKILL.md              ranking injection points (vuln-agnostic)
skills/sqli-payloads/SKILL.md                   context classification + how to read responses
skills/sqli-payloads/references/*.md            3 files: error-based, boolean-blind, time-blind
skills/sqli-payloads/scripts/payloads.py        the FIXED payload set + ERROR_SIGNATURES + select()
agent/prompts.py                                ORCHESTRATOR / TRIAGE / REPORT + DVWA variable dict
eval/ground_truth.py                            6 hand-labelled cases + deterministic scorer
```

Those five prompts and both skills are **written and tested**. Do not let an
assistant rewrite them — read them and build against them.

### What does NOT exist yet (an assistant will assume it does — it must build it)

```
core/          session.py · browser.py · prober.py · verdict.py
agent/         pipeline.py · config.py · stubs.py
eval/          run_eval.py
chatbot.py     build_index.py     requirements.txt     artifacts/
```

### The port we are allowed to make

The instructor, verbatim: *"Let's build a new deep agent from scratch. That said,
you are welcome to port over anything you have already built."*

tprud9412 has a **working implementation of this exact shape** from last night
(RailsGoat via SAST). It already solves four of our five deliverables, so those
get ported and the team spends its time on the one thing that is genuinely new —
the DAST agent.

| Ported in by tprud9412 | Gives us |
|---|---|
| `build_index.py` + `chatbot.py` | deliverable ③ (chatbot over our findings) |
| `eval_judge.py` (`--consistency --runs 3`) | requirement 2 (evaluation) + requirement 6 evidence |
| staged-chain skeleton and artifact-writing conventions | a shape `agent/pipeline.py` can copy |
| `run_all.ps1` | one-command demo |
| threat-model section layout | the *shape* of deliverable ② — content regenerated for DVWA |

**Port means copy the file and change the domain constants.** It does not mean
"read it for inspiration and rewrite it". We do not have the time.

---

## 1. What we ship

Six requirements and five deliverables, from the instructor's slides. **Both
lists are graded.** Most of our discussion so far has covered deliverable ④ only.

### Requirements

| # | Requirement | Where it lives | Owner |
|---|---|---|---|
| 1 | DeepAgent (real agentic reasoning) | `agent/pipeline.py` | Mike |
| 2 | Evaluation built in | `eval/run_eval.py` + ported judge | tprud9412 |
| 3 | Skill ≥ 1 | `skills/` — we have 2 | done |
| 4 | Custom tool ≥ 1 | the two functions in §2 | Corbin + tprud9412 |
| 5 | Chain of chains | stages 1 → 2 → 3 → 4 | Mike |
| 6 | **Consistency** | fixed payload set + 3 identical runs, diffed | tprud9412 |

### Deliverables

| # | Deliverable | File we hand over | Owner |
|---|---|---|---|
| ① | context assembled into markdown | `artifacts/01_context.md` | Corbin (from crawl output) |
| ② | threat model | `artifacts/02_threat_model.md` | Mike (LLM stage) |
| ③ | chatbot answering questions about the app and findings | `chatbot.py` | tprud9412 (port) |
| ④ | deep agent identifying vulns (1 skill + 1 custom tool) | the whole pipeline | all three |
| ⑤ | final report | `artifacts/05_report.md` | Mike (stage 4) |

**Requirement 6 is the easiest to fail and the hardest to fake.** It is why the
payload set is fixed in code and why the LLM never invents a payload.

---

## 2. The contract

**Two functions. Nothing else crosses the boundary.**

```
harness  →  tool layer           →  target app
 (Mike)     (Corbin + tprud9412)    (DVWA)
```

- The tool layer holds **what it can do** — crawl, fire payloads, judge evidence.
- The harness holds **when to do what** — the LLM ranks parameters, orders the
  steps, writes the report.

**These names are frozen.** They appear in `agent/prompts.py`, in the tool
registry, and in the module that implements them. One name each, no aliases.

```python
def enumerate_endpoints(url: str, auth: dict | None = None) -> list[dict]:
    """Crawl the target with Playwright and return every parameter it accepts.
    Does NOT test anything.

    Returns: [{"url": str,            # full URL, including scheme and host
               "method": "GET"|"POST",
               "param": str,          # ONE parameter per row — never a list
               "value": str,          # its original value, as seen
               "requires_auth": bool}]
    """

def evaluate_sqli(url: str, method: str, param: str, context: str,
                  original_value: str = "") -> dict:
    """Fire a FIXED payload set at ONE parameter and report evidence.
    This function decides the verdict. The LLM does not.

    context: "numeric" | "string" | "unknown"   <- the LLM classifies this
    original_value: value seen during enumeration. Payloads are APPENDED to it,
        so id=1 is probed as id=1' — not as id='. Empty means replace the value.

    Returns: {"confirmed": bool,
              "technique": "error-based"|"boolean-blind"|"time-blind"|"none",
              "evidence": str,        # verbatim observation, never a summary
              "payload": str,         # the exact payload that worked
              "stage_reached": int,   # 1, 2 or 3 — how far it had to go
              "requests_used": int,
              "error": str | None}    # set when the attempt could not run
    """
```

**`error` is not politeness.** A parameter behind a login we never reached is
*undetermined*, not safe, and `confirmed: false` alone cannot express that. When
`error` is non-null, the report lists that point as **not tested**.

**`method` and `context` are load-bearing.** Drop `method` and every POST
injection point becomes untestable. Drop `context` and the LLM has no way to
select a payload group — which destroys requirement 6, because payload choice
moves back into the model.

### Authentication belongs to the tool layer, not to an argument

`evaluate_sqli` cannot log in per call — that burns a login per parameter and
DVWA will lock the account. **One session is created at startup and both
functions share it.** `auth` on `enumerate_endpoints` only overrides the default
credentials.

`core/session.py` owns: the login POST, the `PHPSESSID` + `security=low` cookies,
the allow-list, the request counter, and the inter-request delay. **Corbin writes
it, tprud9412 consumes it.** It is the one file two people touch — agree on
`Session.get/post` before either of you starts.

---

## 3. The 4 stages

| # | Who runs it | In | Out |
|---|---|---|---|
| 1 Enumerate | tool `enumerate_endpoints` | target url | list of parameters |
| 2 **Triage** | **LLM** + both skills | list of parameters | ranked subset + `context` each |
| 3 Confirm | tool `evaluate_sqli` | one parameter at a time | verdict with evidence |
| 4 **Report** | **LLM** | verdicts | final report + threat model |

**Stage 2 must not decide whether anything is vulnerable.** It ranks, and it
classifies numeric/string. **Stage 3 is the only thing that sets `confirmed`.**

We hit this exact failure yesterday: one stage emitted a *plan* while the next
expected *findings*, and the chain stalled. Freeze the shapes before writing logic.

> The team diagram says *"SQLi Testing Skill + analysis agents review evidence and
> identify findings."* **That wording contradicts the design and has to be read as
> "present and explain evidence".** The skill teaches the agent how to read a
> response; the code decides the verdict. Fix the diagram before the demo — a
> grader will ask which of the two is true.

### Rules that keep the results consistent

1. **The payload list is fixed and lives in code.** The LLM never invents payloads.
2. **The LLM classifies context; the code selects payloads from that.**
   Same classification in → same requests out → same result across runs.
3. **A verdict requires evidence returned by the tool.** Reading a response and
   concluding "this looks injectable" is not evidence.
4. **Silence at one stage means undetermined, not safe.** Report *not vulnerable*
   only after all three techniques have been tried.

| Technique | Confirmed when |
|---|---|
| error-based | response body contains a known DB error signature |
| boolean-blind | TRUE ≈ baseline **and** FALSE ≠ baseline (asymmetry) |
| time-blind | response ≥ baseline + 4s, **reproduced twice in a row** |

One slow response is not evidence. Reproduce it.

---

## 4. Run and verify

```powershell
# The Windows console must be UTF-8 or writing Korean artifacts will crash
$env:PYTHONIOENCODING = "utf-8"

python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium          # Corbin only

# target — each of us runs our own during development
docker run -d -p 8080:80 vulnerables/web-dvwa
#   http://localhost:8080/setup.php   -> Create / Reset Database
#   login admin / password
#   /security.php                     -> security level "low"
```

**Every component must be verifiable alone. Nobody waits on anybody.**

```powershell
python skills\sqli-payloads\scripts\payloads.py   # payload set summary
python eval\ground_truth.py                       # label counts + VERIFY list
python -c "from core.prober import evaluate_sqli; print(evaluate_sqli('http://localhost:8080/vulnerabilities/sqli/','GET','id','numeric','1'))"
python -c "from core.browser import enumerate_endpoints; print(len(enumerate_endpoints('http://localhost:8080')))"
python agent\pipeline.py --target http://localhost:8080
python eval\run_eval.py --runs 3                  # scores + consistency evidence
```

DVWA runs MariaDB, so MySQL syntax applies: `SLEEP()`, `-- ` with a **trailing
space**, `information_schema`.

**Only test the local instance or the one URL in `ALLOWED_TARGETS`.** The
allow-list is enforced in `core/session.py`, not in a prompt.

---

## 5. Coding rules

These come from failures we actually hit yesterday. They are not style opinions.

- **Windows is in the mix.** Always `open(..., encoding="utf-8")`. Do not print
  non-ASCII symbols — a cp949 console dies on them.
- **Do not swallow failures.** Never catch an exception and return a
  plausible-looking string. A fake result flowing into the next stage poisons the
  whole run. Raise, or fill in the `error` field.
- **Never `json.loads()` a raw LLM response.** Extract the JSON block, fall back
  to label regex, and if both fail record a **parse failure** — not a zero score.
- **Model IDs live in `agent/config.py` only.**
- **Literal braces in prompt templates must be doubled:** `{{ }}`.
- **Tool `description` fields are a full paragraph.** Short ones cause missed
  tool calls.
- **`skills/` holds markdown and data, not orchestration.** `payloads.py` sits
  under `skills/sqli-payloads/scripts/` on purpose — the skill and its payload set
  travel together and can be copied into another project as one folder. `core/`
  imports it; nothing under `skills/` imports `core/` or `agent/`.

---

## 6. Work orders

Give your assistant **§0 through §5, plus your own subsection.** Each one ends in
a command that proves it works without anyone else's code.

### @tprud9412 — verdict logic, evaluation, chatbot

1. `core/verdict.py` — the only place a verdict is decided. Three pure functions:
   no HTTP, no LLM.
   ```python
   def judge_error_based(body: str) -> tuple[bool, str]
   def judge_boolean_blind(baseline: str, t: str, f: str) -> tuple[bool, str]
   def judge_time_blind(t0: float, t1: float, t2: float) -> tuple[bool, str]
   ```
   The rules are already written out in `skills/sqli-payloads/references/*.md`.
   **The code and those documents must correspond 1:1** — that pairing is what we
   put on screen during the demo.
2. `core/prober.py` — `evaluate_sqli()`. Walks stage 1 → 2 → 3, stops at the first
   confirmation, returns the contract dict. Every request goes through
   `core/session.py`. **Raw HTTP, not Playwright:** time-blind needs clean timing
   and boolean-blind needs raw byte comparison; a browser adds variance to both.
3. `eval/run_eval.py` — run the pipeline, parse the stage-4 labels into
   `{"url","method","param","vulnerable","technique"}`, call `grade()`, write
   `artifacts/06_evaluation.json`. **`grade()` keys on a path while the contract
   returns a full URL — normalise before comparing, or every case scores as a
   miss.** Also count findings the report claims that ground truth never listed.
4. Consistency evidence: three runs against the same target, diff the confirmed
   set. Port the harness from last night's `eval_judge.py --consistency --runs 3`.
5. Port `build_index.py` + `chatbot.py`, repoint them at our `artifacts/`. Keep
   `--selftest`.

Verify: `python eval\ground_truth.py`, then `evaluate_sqli(...)` against local
DVWA returns `confirmed: True` with a MariaDB error string in `evidence`.

### @Corbin — crawler, session, target

1. `core/session.py` **first — Mike and tprud9412 are both blocked on it.**
   Login, cookie jar (`PHPSESSID` + `security=low`), allow-list, request counter,
   delay. A URL outside the allow-list raises. Going over budget raises.
   **DVWA's login form carries a `user_token` CSRF field that changes on every
   render — fetch the page and read the token before each POST**, or every POST
   test fails for the wrong reason.
2. `core/browser.py` — `enumerate_endpoints()` with Playwright. One row per
   parameter. Reuse the session cookies so authenticated pages are reachable.
   Where the crawler cannot reach, emit the row with `requires_auth: true` rather
   than dropping it — **a redirect to login is "not reached", not "not
   vulnerable"**.
3. Deploy one shared DVWA, put its URL in `agent/config.py:ALLOWED_TARGETS`, and
   post the URL in Slack the moment it is up.
4. Write `artifacts/01_context.md` from the crawl result. That markdown **is
   deliverable ①**, so it needs headings and prose — not a JSON dump.

Verify: `enumerate_endpoints("http://localhost:8080")` returns rows including
`/vulnerabilities/sqli/` `GET` `id`.

### @Mike — harness, pipeline, report

1. **Start against stubs. Do not wait for us.** Copy this into `agent/stubs.py` —
   it covers the vulnerable, the clean, and the failed branch, so the harness gets
   exercised on all three:
   ```python
   def enumerate_endpoints(url, auth=None):
       return [
           {"url": f"{url}/vulnerabilities/sqli/", "method": "GET",
            "param": "id", "value": "1", "requires_auth": True},
           {"url": f"{url}/vulnerabilities/sqli/", "method": "GET",
            "param": "Submit", "value": "Submit", "requires_auth": True},
           {"url": f"{url}/login.php", "method": "POST",
            "param": "username", "value": "admin", "requires_auth": False},
       ]

   def evaluate_sqli(url, method, param, context, original_value=""):
       if param == "id":
           return {"confirmed": True, "technique": "error-based",
                   "evidence": "You have an error in your SQL syntax", "payload": "'",
                   "stage_reached": 1, "requests_used": 4, "error": None}
       if param == "Submit":
           return {"confirmed": False, "technique": "none", "evidence": "",
                   "payload": "", "stage_reached": 3, "requests_used": 11, "error": None}
       return {"confirmed": False, "technique": "none", "evidence": "",
               "payload": "", "stage_reached": 0, "requests_used": 0,
               "error": "redirected to login.php - not reached"}
   ```
   At integration we swap a single import line.
2. `agent/pipeline.py` — `create_deep_agent()` with the two tools plus the triage
   and report subagents. The prompts are **already written** in `agent/prompts.py`;
   call `build(TRIAGE)` rather than writing new ones.
   **Trap:** `FilesystemBackend(root_dir=...)` must contain `skills/`, or skill
   loading dies with a `ValueError`. Point `root_dir` at the repo root.
3. `agent/config.py` — model IDs, `ALLOWED_TARGETS`, `MAX_REQUESTS = 300`,
   `REQUEST_DELAY_SEC = 0.2`, DVWA credentials. Nothing hardcoded elsewhere.
4. Stage 4 writes **two** files: `artifacts/05_report.md` (deliverable ⑤) and
   `artifacts/02_threat_model.md` (deliverable ②). The threat model is a separate
   LLM call over the same evidence — entry points, trust boundaries, and what an
   attacker gains from a confirmed SQLi.

Verify: `python agent\pipeline.py --target http://localhost:8080` against the
stubs produces both artifacts with no tool layer present.

---

## 7. Integration and demo

| Time | What |
|---|---|
| **T-90** | `core/session.py` frozen and pushed. Everyone pulls. |
| **T-60** | Mike swaps stubs for the real imports. First end-to-end run. |
| **T-45** | Fix false positives and false negatives against `eval/ground_truth.py`. |
| **T-30** | Three consecutive runs for consistency evidence. **Freeze the code.** |
| **T-20** | `build_index.py` over the final artifacts, `chatbot.py --selftest`. |
| **T-10** | Dry-run the demo on the laptop that presents. |

**Demo order** — open `core/verdict.py` and the matching `references/*.md` side by
side (our strongest moment), then the three-run consistency diff, then the chatbot
answering a question about a confirmed finding.

**Closing line:** adding command injection later touches one new `skills/` folder
and one function in `verdict.py`. The harness and the contract do not change.

**Our differentiator, in one table:**

| | SQLmap | us |
|---|---|---|
| parameters tested | all of them | ranked subset only |
| requests | hundreds to thousands | tens |
| payload choice | fixed traversal | LLM classifies context, code selects the group |
| target load | large — we have watched a small instance die | small |

---

## 8. Open decisions

Resolve these in Slack, then edit this file. Do not resolve them in code.

1. **MCP server or in-process tools.** The diagram says a new MCP server; the
   lecture example wires LangChain `BaseTool` objects straight into
   `create_deep_agent`. Both satisfy "custom tool ≥ 1". **Recommendation: write
   the two functions as plain Python and wrap them as `BaseTool` first** — that
   path is proven and runs today — then add the MCP wrapper only if we are ahead
   at T-30. The functions are identical either way, so this blocks nobody.
2. **Shared target or local.** Until Corbin's instance is up, `ALLOWED_TARGETS`
   stays `localhost`. Time-blind against a shared instance is slow and noisy — if
   we go shared, consider skipping stage 3 there.
3. **Scope of "context" for deliverable ①.** Crawl output only. The diagram's
   "source review" would mean SAST, which the instructor explicitly told us not to
   combine with DAST today.
