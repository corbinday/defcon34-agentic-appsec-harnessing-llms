# time-blind SQL Injection - Decision Criteria

**This is the last resort.** Use it only when stage 1 and stage 2 both stayed silent.

## Why it comes last

| Problem | Detail |
|---|---|
| **Slow** | 5 seconds per payload. With reproduction checks, over 10 seconds per case |
| **False positives are common** | Network latency and server load are easily mistaken for SQLi |
| **Load on the target** | `SLEEP()` holds a DB connection for the whole duration |

> **If the target is shared, skipping this stage is a valid choice.**
> In today's lab an account got locked out from repeated requests.

## How it works

Even when the response body shows no difference at all, **delaying only when the condition is true**
turns the response time itself into a signal.

```sql
SELECT * FROM users WHERE id = '1' AND SLEEP(5)
                                       ^-- if this runs, the response comes back 5 seconds late
```

## Payloads

**MySQL / MariaDB** (DVWA target)

```
' AND SLEEP(5)--<SP>          string context
 AND SLEEP(5)--<SP>           numeric context
```

`<SP>` is a single literal space. **The space after `--` is mandatory** -- MySQL
and MariaDB do not treat a bare `--` as a comment. The authoritative strings live
in `scripts/payloads.py`; if the two disagree, the file is right.

> **AND only, never OR.** `' OR SLEEP(5)` makes the condition true for every row,
> and MySQL evaluates SLEEP once per row -- a five-row table answers after 25
> seconds, not 5. That blows the request timeout, reads as a hang rather than a
> delay, and holds a database connection open the whole time.

When porting to another DBMS, this is the only part that changes.

| DBMS | Delay function |
|---|---|
| MySQL / MariaDB | `SLEEP(5)` |
| PostgreSQL | `pg_sleep(5)` |
| MSSQL | `WAITFOR DELAY '0:0:5'` |
| Oracle | `dbms_pipe.receive_message(('a'),5)` |

## IMPORTANT: Confirmation criteria - reproduction is the core

```
[1] baseline request -> measure response time t0     (measure twice, take the average)
[2] delay payload    -> response time t1
[3] Is t1 >= t0 + 4 seconds?
        No  -> not vulnerable
        Yes -> go to [4]
[4] IMPORTANT: send the same payload one more time -> t2
        Is t2 >= t0 + 4 seconds?
                No  -> not vulnerable (it was a one-off delay)
                Yes -> vulnerable - time-blind confirmed
```

> **A single delay is not evidence.** It must reproduce twice in a row.
> The threshold is 4 seconds for a `SLEEP(5)` payload to leave room for network round-trip time.

## Decision table

| baseline | 1st | 2nd | Verdict |
|---|---|---|---|
| 0.3s | 5.4s | 5.3s | **Vulnerable - time-blind confirmed** |
| 0.3s | 5.4s | 0.4s | Not vulnerable - incidental delay |
| 0.3s | 0.5s | - | Not vulnerable |
| **3.0s** | 5.4s | 5.3s | **Undetermined** - the baseline is already slow. The gap is insufficient |

**If the page's baseline is already slow, this technique cannot be used.**
In that case, raise the `SLEEP` value to 10 seconds and retry, or give up on the verdict and leave it as `Undetermined`.

## Common misjudgments

**1. The server is just occasionally slow**

-> Measure the baseline **at least twice** and establish the variance first. If the variance is large, this technique is meaningless.

**2. Mistaking a timeout for a delay**

No response at all (timeout) is different from a normal response 5 seconds later.
**Only a normal response that arrived late** counts as evidence.

**3. The server is backed up by other requests**

If we are sending several requests in parallel, they slow each other down.
**Send requests serially during the time-blind stage.**

## What the tool returns when this technique confirms

These fields come back from `evaluate_sqli`. **You never write them yourself** --
the skill classifies context, the tool decides the verdict, and the report
carries these values through unchanged.

```
PARAM: id
CONTEXT: numeric
CONTEXT_REASON: original value is "1"
STAGE_REACHED: 3
VULNERABLE: Yes
TECHNIQUE: time-blind
EVIDENCE: baseline 0.31s / 0.28s, payload 1st 5.42s, 2nd 5.38s - reproduced twice
PAYLOAD:  AND SLEEP(5)--<SP>
```
