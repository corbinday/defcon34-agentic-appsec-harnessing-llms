---
name: sqli-payloads
description: "Use this skill when you need to decide WHICH SQL injection payloads to fire at a specific parameter, and how to interpret the responses. It does not generate payloads - it classifies the parameter's context so a fixed payload set can be selected deterministically. Use it after injection points have been discovered."
license: MIT
metadata:
  author: defcon-training-group
  version: "1.0"
  target: "MySQL / MariaDB (DVWA)"
---

# SQL Injection Payload Selection Skill (CWE-89)

## What this skill does / does not do

| Does | Does not |
|---|---|
| **Determines the context** of a parameter (numeric / string) | **Does not invent payloads** |
| Decides which **stage** to go to | Does not make the **final vulnerability call** |
| Tells you **how to read** the responses | Does not send requests itself (the tool does) |

> **The payload list is fixed in `scripts/payloads.py`.**
> You do not pick from the list. **You only determine the context**, and the code fires that entire group.
> This is what makes the same input produce the same requests, and results reproducible across runs.

## Stage 1 - Determine the parameter context

Look at the **original value** of the given parameter and classify it as one of two.

| Verdict | Basis | Example |
|---|---|---|
| `numeric` | Value consists of digits only | `id=1`, `page=3`, `user_id=42` |
| `string` | Value mixes letters or symbols | `name=admin`, `q=hello`, `sort=asc` |
| `unknown` | Value is empty or undecidable | `id=` |

If `unknown`, **treat it as `string`**. String payloads cover more ground.

**Always record the basis for the verdict in one line.** This is so it can be traced back later.

## Stage 2 - Decide the stage

**Always start at stage 1. Do not skip.**

| stage | Technique | When | Cost |
|---|---|---|---|
| **1** | error-based | **Always first** | 4-5 requests, fast |
| **2** | boolean-blind | When stage 1 stayed silent | 4 requests, moderate |
| **3** | time-blind | When both stage 1 and 2 stayed silent | 2-4 requests, **slow (5 seconds each)** |

> **Why the order matters** - if error-based hits, you stop there.
> There is no reason to run the later stages, and it avoids putting needless load on the target server.
> **This is the difference between us and SQLmap** - SQLmap fires everything.

## Stage 3 - How to read the responses

### error-based

If the response body contains a **DB error fingerprint**, that is confirmation.
The fingerprint list lives in `ERROR_SIGNATURES` in `scripts/payloads.py`.
See `references/error-based.md`.

> The verdict is made by code (`has_sql_error()`). **"It looks like an error" is not a basis for a verdict.**

### boolean-blind

**Always compare in pairs.**

```
baseline          (no payload)
true payload      ' AND '1'='1
false payload     ' AND '1'='2
```

| Result | Verdict |
|---|---|
| true ~= baseline **and** false != baseline | **Vulnerable** |
| true ~= false | Not vulnerable (just reflected) |
| all three differ | **Undetermined** - the page changes on every request anyway |

See `references/boolean-blind.md`.

### time-blind

| Result | Verdict |
|---|---|
| Response time >= baseline + 4 seconds, **reproduced twice in a row** | **Vulnerable** |
| Slow only once | **Not vulnerable** - network latency |

> **A single delay is not evidence.** Always confirm reproduction.

## Stage 4 - Output

Report each parameter in the format below. **Do not write guesses.**

```
PARAM: (str) parameter name
CONTEXT: numeric | string | unknown
CONTEXT_REASON: (str) one line on why you decided that
STAGE_REACHED: 1 | 2 | 3
VULNERABLE: Yes | No | Undetermined
TECHNIQUE: error-based | boolean-blind | time-blind | none
EVIDENCE: (str) what was actually observed. Raw error fingerprint, response length difference, delay time, etc.
PAYLOAD: (str) the raw payload used for confirmation
```

**Use `VULNERABLE: Yes` only when the tool returned evidence.**
Do not infer it from reading the code, and do not write it because "it seems likely."
If you could not confirm it, it is `Undetermined`. **Use `No` only after all three stages have been run.**

## Target DBMS

Based on **MySQL / MariaDB**. DVWA uses MariaDB, and MySQL attack techniques work as-is.

- Comments: `-- ` (trailing space required), `#`
- Delay: `SLEEP(n)`
- Metadata: `information_schema`

To move to a different DBMS, replace only `scripts/payloads.py`. This document stays as it is.

## What not to do

- **Do not invent payloads on the fly.** If it is not in the list, do not use it.
- **Do not fire at every parameter.** Follow the priority from the endpoint discovery results.
- **Do not report anything unconfirmed as vulnerable.**
- Targets are **local/designated instances only**. The allowlist is enforced by the tool.
