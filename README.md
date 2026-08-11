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

```powershell
$env:PYTHONIOENCODING = "utf-8"

python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium

docker run -d -p 8080:80 vulnerables/web-dvwa
# http://localhost:8080/setup.php -> Create / Reset Database
# login admin / password, then /security.php -> security level "low"

python agent\pipeline.py --target http://localhost:8080
python eval\run_eval.py --runs 3
```

**Only the local instance, or the one URL in `ALLOWED_TARGETS`.** The allow-list
is enforced in code, not in a prompt.

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
