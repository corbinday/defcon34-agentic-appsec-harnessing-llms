---
name: endpoint-discovery
description: "Use this skill when you need to find and prioritize which endpoints and parameters of a running web application are worth testing for injection. It enumerates injection points and ranks them by how likely they are to reach a database or a command interpreter. Use it BEFORE any payload is fired. It is vulnerability-agnostic - reuse it for SQLi, command injection, or XSS."
license: MIT
metadata:
  author: defcon-training-group
  version: "1.0"
---

# Injection Point Discovery Skill (General Purpose)

> **This skill is not tied to a specific vulnerability class.**
> **Reuse it as-is** when you extend from SQL injection to command injection or XSS.
> That is why there are no payloads here. It covers **only "where to look".**

## What this skill does / does not do

| Does | Does not |
|---|---|
| **Enumerates injectable points** | **Does not fire payloads** |
| **Ranks** which points are most likely to **reach a DB or a command interpreter** | Does not decide whether a point is vulnerable |
| Flags whether authentication is required | Does not crawl by itself (the tool does that) |

## Step 1 - Enumerate the points

Take the list returned by the `enumerate_endpoints` tool.
**One entry is one parameter.** If a URL has 3 parameters, you get 3 entries.

```json
{"url": "http://localhost:8080/vulnerabilities/sqli/", "method": "GET",
 "param": "id", "value": "1", "requires_auth": true}
```

**Check the spots that are easy to miss.**

| Spot | Example |
|---|---|
| URL query parameter | `?id=1&page=2` |
| POST form field | `username`, `password` |
| **Path segment** | `/user/42/profile` -- the numeric slot |
| **Cookie** | `user_id=42` |
| **Header** | `X-Forwarded-For`, `Referer` |

> The tool may fail to pick up paths, cookies, and headers automatically. **Read the response body
> and Set-Cookie and name them yourself.**

## Step 2 - Prioritize. IMPORTANT: this is the core of the skill

**Do not fire at every parameter.** Rank them by the criteria below.

### High - test these first

- Name implies a **record lookup**: `id`, `uid`, `user_id`, `pid`, `no`, `seq`, `idx`
- Name implies **search**: `q`, `search`, `keyword`, `query`, `filter`
- Name implies **sorting or range**: `sort`, `order`, `orderby`, `limit`, `offset`
- Value is **a single number**, and changing it **changes the response content**
- `username` on an authentication page (the classic spot where login bypass works)

### Medium

- Ordinary text fields in a form (`name`, `title`, `comment`)
- Values picked from a fixed list (`category`, `type`)

### Low - only if time remains

- **Control fields** such as `Submit`, `csrf_token`, `_method`
- Values that appear to be fixed constants
- Static asset paths (`.css`, `.js`, `.png`)

> **Do not hit button fields like `Submit` first.** They only add load to the target and almost never hit.

### Responsiveness check (optional, 1 request)

Change the value **slightly, staying inside the normal range**, and see whether the response changes.

```
id=1  ->  id=2      response differs  -> likely a DB lookup -> raise priority
                    response is same  -> parameter may be unused -> lower priority
```

**This is not a payload.** The value is normal, so it puts no strain on the target.

## Step 3 - Handle authentication

Points with `requires_auth: true` **cannot be reached without a session.**
If you get redirected to the login page, that result is **"not reached", not "not vulnerable".**

> If you cannot tell those apart, **you miss every vulnerability behind authentication.**
> Most of the attack surface sits behind login.

Keeping the session alive is the tool's responsibility. This skill **only flags the fact that authentication is required.**

## Step 4 - Output

**These labels are parsed by regex.** They match `agent/prompts.py` exactly; if
you change one, change it in both places or the chain drops the stage.

Two counters first:

```
TOTAL_POINTS: (int) total number of points enumerated
SELECTED: (int) number of points that will actually be tested
```

Then one block per selected point, no wrapping list, no indentation:

```
URL: (str) full url
METHOD: GET | POST
PARAM: (str) one parameter name
PRIORITY: high | medium
CONTEXT: numeric | string | unknown
CONTEXT_REASON: (str) one line - what the original value looked like
REASON: (str) one line - why this parameter is worth testing
REQUIRES_AUTH: true | false
```

**`SELECTED` must be smaller than `TOTAL_POINTS`.**
If you select everything, there is no point in using this skill.
**How much you cut down is exactly what differentiates our tool**, so always record the numbers.

## Why we cut down (say this in the talk)

| | Brute-force tools | Us |
|---|---|---|
| Target parameters | All of them | **Only the top-ranked ones** |
| Request count | Hundreds to thousands | Dozens |
| Load on target | Large - there are real cases of the server going down | Small |

> A real incident from the training: an agent was let loose and sent **200 to 1000 requests at once**,
> and **a small EC2 instance went down.** In today's lab, repeated attempts also **locked an account.**
> **Cutting down is itself a feature.**

## Extension (not today, mention it in the talk)

Keep the same ranking criteria and **only swap the payload skill that comes after it** to move to another vulnerability class.

| Vulnerability | Parameter names that get higher priority |
|---|---|
| SQL injection | `id`, `q`, `sort`, `order` |
| Command injection | `host`, `ip`, `cmd`, `ping`, `file` |
| Path traversal | `file`, `path`, `page`, `include`, `template` |
