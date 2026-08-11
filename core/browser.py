"""enumerate_endpoints -- crawl the target and list every parameter it accepts.

OWNER: Corbin. **This is a stand-in, not the deliverable.** It walks a seed list
with plain HTTP and regex so the chain runs end to end today. Replace the body
with Playwright; keep the return shape, because triage and the prober both key
off it.

What the real one must add:
  - follow links instead of using a seed list
  - path segments (/user/42/profile) and cookies, which regex over HTML misses
  - values rendered by JavaScript

What it already gets right, and must keep: one row per parameter, and every
other field of the same form carried along in `siblings`. Without those the
prober sends a parameter in isolation and DVWA never runs the query.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.I | re.S)
ACTION_RE = re.compile(r"action=['\"]([^'\"]*)['\"]", re.I)
METHOD_RE = re.compile(r"method=['\"]([^'\"]*)['\"]", re.I)
INPUT_RE = re.compile(r"<(?:input|select|textarea)\b[^>]*>", re.I)
NAME_RE = re.compile(r"name=['\"]([^'\"]+)['\"]", re.I)
VALUE_RE = re.compile(r"value=['\"]([^'\"]*)['\"]", re.I)
TYPE_RE = re.compile(r"type=['\"]([^'\"]+)['\"]", re.I)

# Where DVWA keeps its exercises. The real crawler discovers these.
SEEDS = [
    "/vulnerabilities/sqli/",
    "/vulnerabilities/sqli_blind/",
    "/vulnerabilities/brute/",
    "/vulnerabilities/exec/",
    "/vulnerabilities/xss_r/",
    "/security.php",
]

SKIP_TYPES = {"submit", "button", "image", "reset"}


def _fields(form_html):
    out = []
    for tag in INPUT_RE.findall(form_html):
        name = NAME_RE.search(tag)
        if not name:
            continue
        value = VALUE_RE.search(tag)
        ftype = TYPE_RE.search(tag)
        out.append((name.group(1),
                    value.group(1) if value else "",
                    (ftype.group(1) if ftype else "text").lower()))
    return out


def enumerate_endpoints(url, auth=None, session=None):
    if session is None:
        raise ValueError("enumerate_endpoints needs a core.session.Session")

    points = []
    seen = set()
    for path in SEEDS:
        try:
            resp = session.get(path)
        except Exception:
            continue                      # a page we cannot reach is not a finding
        requires_auth = "login.php" in resp.url
        page_url = resp.url.split("?")[0]

        for form in FORM_RE.findall(resp.text):
            action = ACTION_RE.search(form)
            method = (METHOD_RE.search(form).group(1).upper()
                      if METHOD_RE.search(form) else "GET")
            target = urljoin(page_url, action.group(1)) if action and action.group(1) else page_url
            fields = _fields(form)
            if not fields:
                continue

            for name, value, ftype in fields:
                # Submit buttons stay out of the list as injection points, but
                # they still have to ride along in siblings -- DVWA will not run
                # the query without them.
                if ftype in SKIP_TYPES and name.lower() not in ("submit", "login"):
                    continue
                key = (target, method, name)
                if key in seen:
                    continue
                seen.add(key)
                points.append({
                    "url": target,
                    "method": method,
                    "param": name,
                    "value": value,
                    "siblings": {n: v for n, v, _ in fields if n != name},
                    "requires_auth": requires_auth,
                })
    return points
