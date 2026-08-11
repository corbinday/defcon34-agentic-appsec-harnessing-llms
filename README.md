# SQLi DAST Agent — DEF CON 34 Training group project

A deep agent that finds **CWE-89 (SQL Injection)** in a running web application.
Target: **DVWA** (PHP / MariaDB).

**One line:** enumerate injection points deterministically, let the LLM decide
*where to look*, and let evidence decide *what is vulnerable*.

| The LLM decides | The code decides |
|---|---|
| which parameters are worth testing | which payloads get fired (fixed list) |
| numeric vs string context | whether a response proves injection |
| how the report reads | request budget and allow-list |

That split is what keeps runs consistent: same judgement in, same requests out.

## Read this before writing code

**[AGENTS.md](AGENTS.md)** — the contract, the coding rules, and a work order per
person. Point your AI assistant at it, then at your own section.

## Run

**Use a virtual environment.** Not a style preference: the run has to reproduce
on someone else's machine, and "works here" is not a result anyone can check.

macOS / Linux:

```sh
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

Windows (PowerShell):

```powershell
$env:PYTHONIOENCODING = "utf-8"
python -m venv venv; .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium
```

Bedrock credentials go in a `.env` file at the repo root. It is git-ignored:

```
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
```

Then, on either platform:

```sh
python agent/pipeline.py --target https://dvwa-production-a515.up.railway.app
python eval/run_eval.py  --target https://dvwa-production-a515.up.railway.app --runs 3
```

Add `--llm` to run stages 2 and 4 through the deep agent instead of the
deterministic stubs. Stages 1 and 3 already go through the MCP server; `--direct`
bypasses it, for debugging only.

**You will see the browser.** Stage 1 is a real Playwright crawl and it runs
visibly, because a seed list cannot be mistaken for a window walking the target.
Turn it off only where no window can open - a container, CI, SSH with no display:

```powershell
$env:DAST_HEADLESS = "1"       # bash: export DAST_HEADLESS=1
```

**The target is always an argument.** Our shared DVWA lives at
`https://dvwa-production-a515.up.railway.app`; run a local container while you
iterate so you are not hammering it:

```sh
docker run -d -p 8080:80 vulnerables/web-dvwa
# http://localhost:8080/setup.php -> Create / Reset Database
# login admin / password, then /security.php -> security level "low"
```

**Only hosts listed in `ALLOWED_TARGETS` are reachable.** The allow-list is
enforced in code, not in a prompt.

## Layout

```
agent/     pipeline, prompts, config          the LLM runs only here
core/      session, browser, prober, verdict  deterministic - works with no LLM
skills/    endpoint-discovery, sqli-payloads  markdown + data, no orchestration
eval/      ground_truth, run_eval             consumes pipeline output, never the reverse
artifacts/ the five deliverables
```

`core/verdict.py` is the only place a verdict is decided. That is deliberate — it
is one file we can open on screen to show exactly why we called something
vulnerable.

## Extending it

Adding command injection later touches one new `skills/` folder and one function
in `core/verdict.py`. The harness and the two-function contract do not change.
