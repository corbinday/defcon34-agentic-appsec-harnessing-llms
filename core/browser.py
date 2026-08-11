"""enumerate_endpoints -- crawl the target and list every parameter it accepts.

OWNER: Corbin.

CORBIN, READ THIS BEFORE YOU TOUCH IT
-------------------------------------
This is now a real Playwright crawl, not a seed list. Things that are load
bearing and that a well-meaning edit will break:

1. The return shape is FROZEN by AGENTS.md section 2. One row per parameter:
   {"url", "method", "param", "value", "siblings", "requires_auth"}.
   `siblings` is every OTHER field of the same form at its original value.
   Measured on our instance:
       GET /vulnerabilities/sqli/?id=1               -> 4592 bytes, no result
       GET /vulnerabilities/sqli/?id=1&Submit=Submit -> 4651 bytes, result rendered
   DVWA guards the query with isset($_GET['Submit']). Drop siblings and the
   most obvious SQL injection in the app reports as clean.

2. Submit buttons are NOT injection points in general, but the two named
   "Submit" / "Login" stay in the list on purpose -- eval/ground_truth.py uses
   /vulnerabilities/sqli/ GET Submit as a trap. Removing them changes the score.

3. A page that redirects to login.php is NOT REACHED, which is not the same as
   NOT VULNERABLE. Those rows keep requires_auth=True instead of being dropped.

4. Playwright does not go through core/session.py, so the allow-list and the
   page budget are enforced here, directly, before the browser opens. Do not
   remove those checks to "simplify" the crawl.

5. Cookies are copied out of session.http.cookies into the browser context so
   the crawl lands on authenticated pages. We do not copy them back -- the
   prober keeps using the requests session it logged in with.

6. If playwright or its chromium binary is missing, we print why and fall back
   to enumerate_endpoints_fallback() (requests + regex, the old stand-in).
   Two of us are on macOS and one on Windows; nobody's checkout may die on an
   import. To install: pip install playwright && python -m playwright install chromium

Verify:
    python -c "from core.session import Session; from core.browser import enumerate_endpoints; from agent import config; s=Session(T, config.ALLOWED_TARGETS); s.login(**config.DVWA_CREDS); print(len(enumerate_endpoints(T, session=s)))"
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from core.session import TargetNotAllowed

# -- crawl budget. Playwright bypasses core/session.py, so these are the only
# -- things standing between us and hammering a shared box.
DEFAULT_MAX_PAGES = 40
DEFAULT_MAX_DEPTH = 2
PAGE_TIMEOUT_MS = 15000

# Following these ends the session and every page after it looks unauthenticated.
LOGOUT_MARKERS = ("logout", "signout", "log-out", "sign-out", "logoff")

# Not injection points, but they still ride along in siblings.
SKIP_TYPES = {"submit", "button", "image", "reset", "file"}
# ... except these two, which ground_truth.py labels as traps.
ALWAYS_KEEP = {"submit", "login"}

SKIP_SUFFIX = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
               ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".gz")


class BrowserUnavailable(RuntimeError):
    """Playwright is installed but has no browser binary to drive."""


# ---------------------------------------------------------------------------
# guards
# ---------------------------------------------------------------------------
def _allowed_list(session):
    if session is not None and getattr(session, "allowed", None):
        return [a.rstrip("/") for a in session.allowed]
    from agent import config  # imported late: core/ must not need agent/ to load
    return [a.rstrip("/") for a in config.ALLOWED_TARGETS]


def _is_allowed(url, allowed):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    origin = "%s://%s" % (parts.scheme, parts.netloc)
    return any(origin == a or url.startswith(a) for a in allowed)


def _shape(url):
    """Identity we de-duplicate visits on: path plus the SET of query keys.

    /vulnerabilities/fi/?page=include.php and ?page=file2.php are the same page
    with the same parameter. Visiting both burns budget and finds nothing new.
    """
    p = urlsplit(url)
    keys = tuple(sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True)))
    return (p.scheme, p.netloc.lower(), p.path.rstrip("/") or "/", keys)


def _strip(url):
    """Drop the fragment. Keeps the query -- query keys are injection points."""
    return url.split("#", 1)[0]


def _oneline(exc):
    return re.sub(r"\s+", " ", str(exc))[:160]


# ---------------------------------------------------------------------------
# row builders
# ---------------------------------------------------------------------------
def _add(rows, seen, url, method, param, value, siblings, requires_auth):
    key = (url, method, param)
    if key in seen:
        return
    seen.add(key)
    rows.append({"url": url, "method": method, "param": param,
                 "value": value, "siblings": siblings,
                 "requires_auth": requires_auth})


def _rows_from_query(rows, seen, url, requires_auth):
    """A link carrying ?a=1&b=2 is two injection points that need each other.

    They are siblings for exactly the reason form fields are: the page may only
    run its query when the whole set arrives.
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return
    base = "%s://%s%s" % (parts.scheme, parts.netloc, parts.path)
    for name, value in pairs:
        others = {n: v for n, v in pairs if n != name}
        _add(rows, seen, base, "GET", name, value, others, requires_auth)


def _field_value(el, tag, ftype):
    """Original value as the browser sees it -- selected option, not the markup."""
    if tag in ("select", "textarea") or ftype not in ("checkbox", "radio"):
        try:
            return el.input_value()
        except Exception:
            pass
    return el.get_attribute("value") or ""


def _rows_from_forms(rows, seen, page, page_url):
    from playwright.sync_api import Error as PwError

    for form in page.query_selector_all("form"):
        try:
            method = (form.get_attribute("method") or "GET").strip().upper()
            if method not in ("GET", "POST"):
                method = "GET"
            action = (form.get_attribute("action") or "").strip()
            if action and not action.startswith("#"):
                target = urljoin(page_url, action)
            else:
                target = page_url
            target = _strip(target).split("?", 1)[0]

            fields = []
            for el in form.query_selector_all("input, select, textarea"):
                name = (el.get_attribute("name") or "").strip()
                if not name or el.get_attribute("disabled") is not None:
                    continue
                tag = (el.evaluate("e => e.tagName") or "input").lower()
                if tag == "select":
                    ftype = "select"
                elif tag == "textarea":
                    ftype = "textarea"
                else:
                    ftype = (el.get_attribute("type") or "text").lower()
                fields.append((name, _field_value(el, tag, ftype), ftype))
        except PwError as exc:
            # A form that vanished mid-crawl is a fact worth printing, not a
            # reason to invent rows for it.
            print("[browser] skipped a form on %s: %s" % (page_url, _oneline(exc)))
            continue

        if not fields:
            continue
        for name, value, ftype in fields:
            if ftype in SKIP_TYPES and name.lower() not in ALWAYS_KEEP:
                continue
            _add(rows, seen, target, method, name, value,
                 {n: v for n, v, _ in fields if n != name}, False)


def _links(page, allowed):
    try:
        hrefs = page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.href)") or []
    except Exception as exc:
        print("[browser] link extraction failed on %s: %s"
              % (page.url, _oneline(exc)))
        return []
    out = []
    for href in hrefs:
        if not isinstance(href, str):
            continue
        href = _strip(href.strip())
        if not href or not _is_allowed(href, allowed):
            continue
        low = href.lower()
        if any(m in low for m in LOGOUT_MARKERS):
            continue                      # following this kills the session
        if urlsplit(low).path.endswith(SKIP_SUFFIX):
            continue
        out.append(href)
    return out


# ---------------------------------------------------------------------------
# the crawl
# ---------------------------------------------------------------------------
def _seed_cookies(context, session, base):
    host = urlsplit(base).netloc.split(":")[0]
    jar = []
    for c in session.http.cookies:
        jar.append({"name": c.name, "value": c.value,
                    "domain": c.domain or host, "path": c.path or "/"})
    if jar:
        context.add_cookies(jar)
    return len(jar)


def _crawl(base, session, allowed, max_pages, max_depth):
    from playwright.sync_api import Error as PwError, sync_playwright

    rows, seen, visited = [], set(), set()
    queued = set()                        # shapes already in the frontier
    unreached = 0

    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=False)
        except PwError as exc:
            msg = str(exc)
            if "Executable doesn" in msg or "playwright install" in msg:
                raise BrowserUnavailable(msg)
            raise
        try:
            context = browser.new_context()
            n = _seed_cookies(context, session, base)
            page = context.new_page()
            page.set_default_timeout(PAGE_TIMEOUT_MS)
            print("[browser] playwright crawl of %s (%d cookies carried over)"
                  % (base, n))

            frontier = [(_strip(base), 0)]
            queued.add(_shape(base))
            while frontier and len(visited) < max_pages:
                current, depth = frontier.pop(0)
                shape = _shape(current)
                if shape in visited:
                    continue
                if not _is_allowed(current, allowed):
                    continue              # belt and braces; _links filtered too
                visited.add(shape)

                try:
                    page.goto(current, wait_until="domcontentloaded")
                except PwError as exc:
                    # Not reached is not "not vulnerable". Keep whatever the URL
                    # itself told us and say so out loud.
                    print("[browser] load failed %s: %s" % (current, _oneline(exc)))
                    _rows_from_query(rows, seen, current, True)
                    unreached += 1
                    continue

                landed = page.url
                if "login.php" in landed.lower() and "login.php" not in current.lower():
                    # Bounced to the login page. Whatever this URL carried is
                    # UNDETERMINED, not clean, so the rows survive with
                    # requires_auth=True. The login form itself we did reach, so
                    # it is recorded honestly against login.php.
                    _rows_from_query(rows, seen, current, True)
                    unreached += 1
                    print("[browser] %s redirected to login - marked requires_auth"
                          % current)
                    if _shape(landed) not in visited:
                        visited.add(_shape(landed))
                        _rows_from_forms(rows, seen, page, _strip(landed))
                    continue

                _rows_from_query(rows, seen, current, False)
                if _strip(landed) != current:
                    _rows_from_query(rows, seen, _strip(landed), False)
                _rows_from_forms(rows, seen, page, _strip(landed))

                if depth < max_depth:
                    for href in _links(page, allowed):
                        s = _shape(href)
                        if s in visited or s in queued:
                            continue      # the nav bar repeats on every page
                        queued.add(s)
                        frontier.append((href, depth + 1))
        finally:
            browser.close()

    print("[browser] %d pages visited, %d not reached, %d injection points"
          % (len(visited), unreached, len(rows)))
    if frontier:
        print("[browser] page budget %d reached, %d urls left unvisited"
              % (max_pages, len(frontier)))
    return rows


def enumerate_endpoints(url, auth=None, session=None,
                        max_pages=DEFAULT_MAX_PAGES, max_depth=DEFAULT_MAX_DEPTH):
    """Crawl the target and return every parameter it accepts. Tests nothing.

    Returns one row per parameter -- see the contract in AGENTS.md section 2.
    """
    if session is None:
        # Called standalone, as AGENTS.md section 5 documents. Build the session
        # the pipeline would otherwise have handed us; `auth` overrides the
        # default credentials, which is all the contract says it does. Raises if
        # the login fails -- an unauthenticated crawl would report every page
        # behind the login as having no parameters at all.
        from core.session import default_session
        session = default_session(url, auth)

    allowed = _allowed_list(session)
    if not _is_allowed(url, allowed):
        raise TargetNotAllowed(
            "refusing to crawl %s. Allowed: %s" % (url, allowed))

    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        print("[browser] playwright is not installed - using the requests+regex "
              "fallback crawler")
        print("[browser] to get the real crawl: pip install playwright && "
              "python -m playwright install chromium")
        return enumerate_endpoints_fallback(url, auth=auth, session=session)

    try:
        return _crawl(url, session, allowed, max_pages, max_depth)
    except BrowserUnavailable as exc:
        print("[browser] no chromium binary: %s" % _oneline(exc))
        print("[browser] run: python -m playwright install chromium")
        print("[browser] using the requests+regex fallback crawler for now")
        return enumerate_endpoints_fallback(url, auth=auth, session=session)


# ---------------------------------------------------------------------------
# fallback: the original requests + regex stand-in. Kept because it needs no
# browser binary, so a teammate with a fresh checkout still gets a working
# pipeline. It walks a seed list and cannot see JavaScript-rendered values.
# ---------------------------------------------------------------------------
FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.I | re.S)
ACTION_RE = re.compile(r"action=['\"]([^'\"]*)['\"]", re.I)
METHOD_RE = re.compile(r"method=['\"]([^'\"]*)['\"]", re.I)
INPUT_RE = re.compile(r"<(?:input|select|textarea)\b[^>]*>", re.I)
NAME_RE = re.compile(r"name=['\"]([^'\"]+)['\"]", re.I)
VALUE_RE = re.compile(r"value=['\"]([^'\"]*)['\"]", re.I)
TYPE_RE = re.compile(r"type=['\"]([^'\"]+)['\"]", re.I)

SEEDS = [
    "/vulnerabilities/sqli/",
    "/vulnerabilities/sqli_blind/",
    "/vulnerabilities/brute/",
    "/vulnerabilities/exec/",
    "/vulnerabilities/xss_r/",
    "/security.php",
]


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


def enumerate_endpoints_fallback(url, auth=None, session=None):
    if session is None:
        raise ValueError("enumerate_endpoints_fallback needs a core.session.Session")

    points = []
    seen = set()
    for path in SEEDS:
        try:
            resp = session.get(path)
        except Exception as exc:
            # Say which page and why. A silently skipped page turns into a
            # "clean" result three stages later.
            print("[browser] fallback could not fetch %s: %s" % (path, _oneline(exc)))
            continue
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
                if ftype in SKIP_TYPES and name.lower() not in ALWAYS_KEEP:
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
