# boolean-blind SQL Injection - Decision Criteria

**Try this when stage 1 (error-based) stayed silent.**
It works even on apps that hide errors.

## Principle

Even with no visible error, **if a true condition and a false condition produce
different responses**, the input is being interpreted as SQL.

```sql
SELECT * FROM users WHERE id = '1' AND '1'='1'   -> condition true  -> rows returned
SELECT * FROM users WHERE id = '1' AND '1'='2'   -> condition false -> no rows
```

## IMPORTANT: Always send three requests

**One request alone proves nothing.** You need a baseline to compare against.

| # | What you send | Name |
|---|---|---|
| 1 | No payload (original value) | **baseline** |
| 2 | True condition | TRUE |
| 3 | False condition | FALSE |

## Payload pairs

**String context**

```
' AND '1'='1        /        ' AND '1'='2
```

**Numeric context**

```
 AND 1=1            /         AND 1=2
```

> **AND only. Never OR.** `' OR '1'='1'-- ` returns every row in the table, so it
> differs from the baseline just like the FALSE payload does — and the decision
> table below needs TRUE to *match* the baseline. Detecting with OR scores a
> genuinely injectable parameter as not vulnerable. OR is for exploitation,
> after detection is done.
>
> The authoritative strings are in `scripts/payloads.py`. If this document and
> that file ever disagree, the file is right and this document is the bug.
>
> Where a payload ends in a comment, `-- ` carries a **mandatory trailing
> space**: MySQL and MariaDB do not treat a bare `--` as a comment. It is
> invisible in a code block, so the file is the place to check it.

## IMPORTANT: Decision table

What do you compare the responses on - look at **body length and core content**.

| baseline | TRUE | FALSE | Verdict |
|---|---|---|---|
| A | **same as A** | **different from A** | **Vulnerable - boolean-blind confirmed** |
| A | different from A | different from A | **Inconclusive** - the page changes on every request anyway |
| A | same as A | same as A | Not vulnerable - the input never reaches the query |

**The key is the asymmetry: "TRUE matches the baseline, only FALSE differs".**
If all three differ, you have no basis for a verdict. Move on to stage 3.

## Comparison method (the code does it)

```python
def looks_same(a: str, b: str) -> bool:
    # Treat as identical if the length differs by 2% or less. Exact matches are rare
    # because of timestamps and tokens
    if not a or not b:
        return a == b
    return abs(len(a) - len(b)) / max(len(a), len(b)) < 0.02
```

> **Length alone can mislead you.** When possible, slice out only the **region where
> result rows are rendered** (for example the `<pre>` block in DVWA) and compare that.
> It is more accurate.

## Common misjudgments

**(1) Calling a dynamic page vulnerable**

If ads, timestamps, or CSRF tokens change on every request, **even two baselines differ.**
-> **Fetch the baseline twice and compare the two.** If those already differ, this
technique is unusable here.

**(2) Mistaking normal app behavior for SQLi**

It can be perfectly normal for `id=1` and `id=1 AND 1=2` to return different responses -
**the second one may simply have been treated as an invalid id.**
That is why the rule requires **the true condition to match the baseline**. That is the
crux of it.

## What the tool returns when this technique confirms

These fields come back from `evaluate_sqli`. **You never write them yourself** --
the skill classifies context, the tool decides the verdict, and the report
carries these values through unchanged.

```
PARAM: id
CONTEXT: numeric
CONTEXT_REASON: original value was "1"
STAGE_REACHED: 2
VULNERABLE: Yes
TECHNIQUE: boolean-blind
EVIDENCE: baseline 1,842 bytes / TRUE(" AND 1=1") 1,842 bytes identical /
          FALSE(" AND 1=2") 1,536 bytes, result row disappeared
PAYLOAD:  AND 1=1  vs   AND 1=2
```
