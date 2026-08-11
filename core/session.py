"""One HTTP session shared by both tools, plus every safety control we have.

OWNER: Corbin. This is a working stand-in so the chain runs end to end today --
replace or harden it, but keep the method signatures, because core/prober.py and
core/browser.py both call them.

Everything that could hurt the target lives here and nowhere else:
  - the allow-list, enforced by raising, never by asking a model nicely
  - the request budget
  - the delay between requests
  - the login, performed once

That last one matters more than it looks. Logging in per parameter would burn a
login for every payload; DVWA also hands out a fresh user_token on every render,
so a POST built from a stale page is rejected and the test fails for a reason
that has nothing to do with SQL injection.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urljoin, urlparse

import requests

TOKEN_RE = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]")


class BudgetExceeded(RuntimeError):
    """The run asked for more requests than we allowed it."""


class TargetNotAllowed(RuntimeError):
    """Something tried to reach a host that is not on the allow-list."""


class Session:
    def __init__(self, base_url, allowed, max_requests=300, delay=0.2, timeout=20):
        self.base_url = base_url.rstrip("/")
        self.allowed = [a.rstrip("/") for a in allowed]
        self.max_requests = max_requests
        self.delay = delay
        self.timeout = timeout
        self.requests_used = 0
        self.http = requests.Session()
        self.http.headers["User-Agent"] = "dvwa-sqli-dast-agent/0.1 (course exercise)"

    # -- guards ------------------------------------------------------------
    def _check(self, url):
        full = url if "://" in url else urljoin(self.base_url + "/", url.lstrip("/"))
        origin = "{0.scheme}://{0.netloc}".format(urlparse(full))
        if not any(origin == a or full.startswith(a) for a in self.allowed):
            raise TargetNotAllowed(
                "refusing to touch %s. Allowed: %s" % (full, self.allowed))
        if self.requests_used >= self.max_requests:
            raise BudgetExceeded(
                "request budget of %d is spent" % self.max_requests)
        return full

    def _send(self, method, url, **kw):
        full = self._check(url)
        if self.delay:
            time.sleep(self.delay)
        self.requests_used += 1
        started = time.time()
        resp = self.http.request(method, full, timeout=self.timeout,
                                 allow_redirects=True, **kw)
        resp.elapsed_seconds = time.time() - started
        return resp

    # -- public ------------------------------------------------------------
    def get(self, url, params=None):
        return self._send("GET", url, params=params)

    def post(self, url, data=None):
        return self._send("POST", url, data=data)

    def csrf_token(self, page_url):
        """Read the user_token this page just minted. It changes every render."""
        m = TOKEN_RE.search(self.get(page_url).text)
        return m.group(1) if m else None

    def login(self, username="admin", password="password"):
        """Log in once. Returns True when the session is usable.

        Success is a redirect away from login.php, not a 200 -- DVWA answers 200
        for a failed login too, with the form rendered again.
        """
        token = self.csrf_token("/login.php")
        data = {"username": username, "password": password, "Login": "Login"}
        if token:
            data["user_token"] = token
        resp = self.post("/login.php", data=data)
        ok = "login.php" not in resp.url and resp.status_code == 200
        if ok:
            self.http.cookies.set("security", "low")
        return ok

    def is_logged_in(self):
        resp = self.get("/index.php")
        return "login.php" not in resp.url
