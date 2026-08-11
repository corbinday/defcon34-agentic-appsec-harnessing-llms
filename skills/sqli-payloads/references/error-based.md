# error-based SQL Injection - Confirmation Criteria

**Try this first.** It takes 4 to 5 requests, and if it hits, you have confirmation on the spot.

## How it works

When input goes straight into a SQL statement, a single quote **breaks the syntax** and the DB throws an error.
If that error is exposed in the response body, **the error itself is the evidence**.

```sql
SELECT * FROM users WHERE id = '$id'
                                 ^ put a ' in id and the quote count becomes odd, causing a syntax error
```

## Payloads and what they target

| Payload | Target context |
|---|---|
| `'` | `WHERE x = 'input'` - single quotes |
| `"` | `WHERE x = "input"` - double quotes |
| `')` | `WHERE (x = 'input')` - wrapped in parentheses |
| `\` | breaks escape handling |
| `1'` | `WHERE id = input` - a quote in a numeric slot |

## IMPORTANT: Confirmation conditions

If **any one of the signatures below** appears in the response body, that is confirmation.
The list lives in `ERROR_SIGNATURES` in `scripts/payloads.py`, and the code makes the call.

```
You have an error in your SQL syntax
check the manual that corresponds to your MariaDB
check the manual that corresponds to your MySQL
mysql_fetch_array()
mysqli_fetch
supplied argument is not a valid MySQL
Unknown column
SQLSTATE[
Warning: mysql
```

> **"It looks like an error page" is not evidence.**
> A 500 response, "Something went wrong", a blank screen - **none of these are evidence**.
> It has to be **text produced by the DB engine**.

## Decision table

| Observation | Verdict |
|---|---|
| DB error signature present | **Vulnerable - error-based confirmed** |
| 500 but no signature | **Undetermined** -> proceed to stage 2 |
| 200 and identical content | **Undetermined** -> proceed to stage 2 |
| App-level validation message such as "Invalid input" | Input validation exists -> proceed to stage 2 |

## Two common misjudgments

**1. Reflection does not mean vulnerable**

The payload showing up verbatim in the response is just **reflection**.
Even if `'` gets printed on the screen, **without a DB error it is not confirmed SQLi**.
(That is actually where you would look for XSS - but that is out of our scope.)

**2. If the app swallows the error, you see nothing**

Production configurations hide DB errors. **error-based failing to hit does not mean the target is safe.**
That is why stage 2 and stage 3 exist. **Silence at stage 1 is not "not vulnerable", it is "undetermined".**

## What the tool returns when this technique confirms

These fields come back from `evaluate_sqli`. **You never write them yourself** --
the skill classifies context, the tool decides the verdict, and the report
carries these values through unchanged.

```
PARAM: id
CONTEXT: numeric
CONTEXT_REASON: original value was "1", digits only
STAGE_REACHED: 1
VULNERABLE: Yes
TECHNIQUE: error-based
EVIDENCE: response contains "You have an error in your SQL syntax; check the manual that
          corresponds to your MariaDB server version"
PAYLOAD: '
```
