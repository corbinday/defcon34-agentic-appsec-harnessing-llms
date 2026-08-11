"""enumerate_endpoints -- crawl the target and list every parameter it accepts.

OWNER: Corbin. Real crawl: starts at the target's landing page and follows
same-origin links instead of walking a fixed seed list, renders each page with
Playwright so JavaScript-set values are read from the live DOM, and reuses the
session's cookies so authenticated pages are reachable without a second login.

What it keeps from the earlier stand-in, because triage and the prober both key
off it: one row per parameter, and every other field of the same form carried
along in `siblings`. Without those the prober sends a parameter in isolation and
DVWA never runs the query.
"""

from __future__ import annotations

import time
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright

SKIP_TYPES = {"submit", "button", "image", "reset"}

# Links a crawl of this target should never follow: they either destroy state
# (logout, database reset) or leave the site entirely.
SKIP_LINK_SUBSTRINGS = ("logout.php", "setup.php", "javascript:", "mailto:")

# Self-imposed, on top of core/session.py's request budget -- Playwright's own
# requests do not go through Session, so the crawl caps itself here instead of
# leaning on that counter. DVWA has ~26 internal pages; 30 covers the whole
# site (verified against the live instance) without letting the crawl run
# unbounded on a target we do not control.
MAX_PAGES = 30


def _same_origin(a, b):
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _field_value(el):
    try:
        return el.input_value()
    except Exception:
        return el.get_attribute("value") or ""


def _fields(form):
    out = []
    for el in form.query_selector_all("input, select, textarea"):
        name = el.get_attribute("name")
        if not name:
            continue
        ftype = (el.get_attribute("type") or "text").lower()
        out.append((name, _field_value(el), ftype))
    return out


def _cookies_for_playwright(session):
    host = urlparse(session.base_url).hostname
    return [{"name": c.name, "value": c.value,
             "domain": c.domain or host, "path": c.path or "/"}
            for c in session.http.cookies]


def enumerate_endpoints(url, auth=None, session=None):
    """Crawl the target with Playwright and return every parameter it accepts.
    Does NOT test anything. See AGENTS.md section 2 for the return contract.
    """
    if session is None:
        raise ValueError("enumerate_endpoints needs a core.session.Session")

    points = []
    seen_params = set()
    visited = set()
    queue = [url.rstrip("/") + "/index.php"]

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context()
        context.add_cookies(_cookies_for_playwright(session))
        page = context.new_page()

        while queue and len(visited) < MAX_PAGES:
            target_url = queue.pop(0)
            page_key = target_url.split("#")[0]
            if page_key in visited:
                continue
            visited.add(page_key)

            if len(visited) > 1 and session.delay:
                time.sleep(session.delay)

            try:
                page.goto(page_key, wait_until="domcontentloaded",
                          timeout=session.timeout * 1000)
            except Exception:
                continue  # a page we cannot reach is not a finding

            requires_auth = "login.php" in page.url
            page_url = page.url.split("?")[0]

            for form in page.query_selector_all("form"):
                action = form.get_attribute("action") or ""
                method = (form.get_attribute("method") or "GET").upper()
                form_target = urljoin(page_url, action) if action else page_url
                fields = _fields(form)
                if not fields:
                    continue

                for name, value, ftype in fields:
                    # Submit buttons stay out of the list as injection points,
                    # but still ride along in siblings -- DVWA will not run
                    # the query without them.
                    if ftype in SKIP_TYPES and name.lower() not in ("submit", "login"):
                        continue
                    key = (form_target, method, name)
                    if key in seen_params:
                        continue
                    seen_params.add(key)
                    points.append({
                        "url": form_target,
                        "method": method,
                        "param": name,
                        "value": value,
                        "siblings": {n: v for n, v, _ in fields if n != name},
                        "requires_auth": requires_auth,
                    })

            for a in page.query_selector_all("a[href]"):
                href = a.get_attribute("href")
                if not href or any(s in href for s in SKIP_LINK_SUBSTRINGS):
                    continue
                dest = urljoin(page_url, href).split("#")[0]
                if _same_origin(dest, url) and dest not in visited:
                    queue.append(dest)

        browser.close()

    return points
