"""Render the run as a single self-contained HTML report.

OWNER: tprud9412.

Why HTML on top of the markdown: the markdown is what the pipeline and the
chatbot read, and the HTML is what a person reads. Two audiences, two formats,
same facts -- both are generated from the same verdict list, so they cannot
drift apart.

One file, no assets, no CDN. It opens from a USB stick, survives being emailed,
and prints. Every style is inline, and the page reads in a light or a dark
browser without asking which one it is in.

The rule that shapes the layout: evidence is quoted, never summarised. A finding
card shows the exact payload and the exact bytes the tool observed, because the
question a reader actually has is "how do you know", and a severity badge does
not answer it.
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

SEVERITY = {
    "error-based": ("critical", "The database returned its own error text"),
    "boolean-blind": ("high", "Responses split on a true/false condition"),
    "time-blind": ("high", "The database was made to wait on command"),
    "none": ("info", ""),
}

CSS = """
:root{
  --bg:#f6f7f9; --panel:#ffffff; --ink:#14161a; --muted:#5b6472; --line:#e3e6ea;
  --accent:#1c4ed8; --crit:#b3261e; --crit-bg:#fdeceb; --high:#a1580b;
  --high-bg:#fdf3e6; --ok:#0f6b3f; --ok-bg:#e8f5ee; --code:#f2f4f7;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#0f1115; --panel:#171a20; --ink:#e8eaed; --muted:#9aa3b0; --line:#272c34;
    --accent:#7aa2ff; --crit:#ff8a80; --crit-bg:#2a1614; --high:#f0b357;
    --high-bg:#2a2013; --ok:#6ddba0; --ok-bg:#12241b; --code:#11141a;
  }
}
:root[data-theme="dark"]{
  --bg:#0f1115; --panel:#171a20; --ink:#e8eaed; --muted:#9aa3b0; --line:#272c34;
  --accent:#7aa2ff; --crit:#ff8a80; --crit-bg:#2a1614; --high:#f0b357;
  --high-bg:#2a2013; --ok:#6ddba0; --ok-bg:#12241b; --code:#11141a;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
  "Malgun Gothic","Apple SD Gothic Neo",sans-serif;}
.wrap{max-width:920px;margin:0 auto;padding:40px 20px 80px}
header{border-bottom:2px solid var(--ink);padding-bottom:18px;margin-bottom:28px}
h1{margin:0 0 6px;font-size:26px;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:14px}
.sub code{background:var(--code);padding:2px 6px;border-radius:4px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
  gap:12px;margin:24px 0 34px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:14px 16px}
.kpi .n{font-size:26px;font-weight:640;letter-spacing:-.02em}
.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;
  letter-spacing:.06em;margin-top:2px}
.kpi.hit .n{color:var(--crit)}
h2{font-size:19px;margin:36px 0 14px;padding-bottom:8px;
  border-bottom:1px solid var(--line)}
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--crit);
  border-radius:10px;padding:18px 20px;margin:14px 0}
.card.high{border-left-color:var(--high)}
.card h3{margin:0 0 4px;font-size:17px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.badge{display:inline-block;font-size:11px;font-weight:600;letter-spacing:.06em;
  text-transform:uppercase;padding:3px 9px;border-radius:20px;margin-right:8px;
  vertical-align:2px}
.badge.critical{background:var(--crit-bg);color:var(--crit)}
.badge.high{background:var(--high-bg);color:var(--high)}
.badge.ok{background:var(--ok-bg);color:var(--ok)}
.why{color:var(--muted);font-size:13px;margin:0 0 14px}
dl{display:grid;grid-template-columns:130px 1fr;gap:8px 16px;margin:0}
dt{color:var(--muted);font-size:13px}
dd{margin:0;min-width:0}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
dd code{background:var(--code);padding:2px 6px;border-radius:4px;font-size:13px;
  word-break:break-all}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;
  padding:12px 14px;margin:0;font-size:12.5px;line-height:1.55;
  overflow-x:auto;white-space:pre-wrap;word-break:break-word}
.clean{background:var(--ok-bg);border:1px solid var(--line);border-left:4px solid var(--ok);
  border-radius:10px;padding:16px 20px}
table{width:100%;border-collapse:collapse;font-size:14px;
  display:block;overflow-x:auto;white-space:nowrap}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
td code{font-size:13px}
.note{color:var(--muted);font-size:13px;background:var(--panel);
  border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin-top:10px}
footer{margin-top:48px;padding-top:18px;border-top:1px solid var(--line);
  color:var(--muted);font-size:12.5px}
@media print{
  body{background:#fff}
  .card,.kpi,.clean,.note{break-inside:avoid}
}
"""


def _e(x):
    return html.escape(str(x if x is not None else ""))


def _kpi(n, label, hit=False):
    return ('<div class="kpi%s"><div class="n">%s</div><div class="l">%s</div></div>'
            % (" hit" if hit else "", _e(n), _e(label)))


def _finding_card(v):
    sev, why = SEVERITY.get(v.get("technique"), ("high", ""))
    return """<div class="card %s">
  <h3><span class="badge %s">%s</span>%s <code>%s</code></h3>
  <p class="why">%s. Confirmed by %s.</p>
  <dl>
    <dt>Endpoint</dt><dd><code>%s</code></dd>
    <dt>Payload</dt><dd><code>%s</code></dd>
    <dt>Evidence</dt><dd><pre>%s</pre></dd>
    <dt>Remediation</dt><dd>%s</dd>
  </dl>
</div>""" % (
        "high" if sev == "high" else "",
        sev, _e(sev), _e(v.get("method", "")), _e(v.get("param", "")),
        _e(why), _e(v.get("technique", "")),
        _e(v.get("url", "")),
        _e(v.get("payload", "") or "(none recorded)"),
        _e(v.get("evidence", "") or "(no evidence recorded)"),
        "Bind this parameter as a query placeholder. In PHP, "
        "<code>mysqli_prepare</code> with <code>bind_param</code> -- never string "
        "concatenation. Escaping the input is not a fix; the value must never be "
        "part of the SQL text.")


def render(target, points, verdicts, elapsed, requests_used, score=None,
           mode="", generated_at=None):
    """Build the HTML. Takes the same data stage 4 already has."""
    hits = [v for v in verdicts if v.get("confirmed")]
    errs = [v for v in verdicts if v.get("error")]
    stamp = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M")

    body = ['<div class="wrap"><header>',
            '<h1>SQL Injection Assessment</h1>',
            '<div class="sub">Target <code>%s</code> &middot; CWE-89 &middot; %s%s</div>'
            % (_e(target), _e(stamp), (" &middot; " + _e(mode)) if mode else ""),
            '</header>']

    body.append('<div class="kpis">')
    body.append(_kpi(len(points), "points found"))
    body.append(_kpi(len(verdicts), "tested"))
    body.append(_kpi(len(hits), "confirmed", hit=bool(hits)))
    body.append(_kpi(requests_used, "requests"))
    body.append(_kpi("%.0fs" % elapsed, "elapsed"))
    body.append("</div>")

    if len(points) and len(verdicts) < len(points):
        body.append('<div class="note">Triage selected <b>%d of %d</b> injection '
                    'points. Testing everything would multiply the load on the '
                    'target for findings the ranking already ruled unlikely.</div>'
                    % (len(verdicts), len(points)))

    body.append("<h2>Confirmed findings</h2>")
    if hits:
        body += [_finding_card(v) for v in hits]
    else:
        body.append('<div class="clean"><b>Nothing was confirmed.</b> An empty '
                    'findings list is a valid result. It is not the same as a '
                    'clean application: it means these parameters produced no '
                    'evidence, and evidence is the only thing we report on.</div>')

    if errs:
        body.append("<h2>Not tested</h2>")
        body.append('<div class="note">These were never reached, so they are '
                    '<b>undetermined</b> -- not safe. Silence at one stage is not '
                    'a clean bill of health.</div><table><tr><th>Endpoint</th>'
                    '<th>Parameter</th><th>Reason</th></tr>')
        for v in errs:
            body.append("<tr><td><code>%s</code></td><td><code>%s</code></td>"
                        "<td>%s</td></tr>"
                        % (_e(v.get("url", "")), _e(v.get("param", "")),
                           _e(v.get("error", ""))))
        body.append("</table>")

    if score:
        body.append("<h2>Scored against ground truth</h2>")
        body.append("<table><tr><th>Precision</th><th>Recall</th><th>F1</th>"
                    "<th>TP</th><th>FP</th><th>FN</th></tr>"
                    "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                    "<td>%s</td><td>%s</td></tr></table>"
                    % (_e(score.get("precision")), _e(score.get("recall")),
                       _e(score.get("f1")), _e(score.get("tp")),
                       _e(score.get("fp")), _e(score.get("fn"))))

    body.append("<h2>How a verdict is reached</h2>")
    body.append("<table><tr><th>Technique</th><th>Confirmed when</th></tr>"
                "<tr><td>error-based</td><td>the response carries a fingerprint "
                "only a database engine produces</td></tr>"
                "<tr><td>boolean-blind</td><td>the TRUE condition matches the "
                "baseline and the FALSE condition does not</td></tr>"
                "<tr><td>time-blind</td><td>the delay clears the threshold and "
                "reproduces on a second request</td></tr></table>")
    body.append('<div class="note">The model never sets a verdict. It ranks '
                'parameters and classifies context; <code>core/verdict.py</code> '
                'decides, from evidence the tool observed. Every payload above '
                'came from a fixed set in <code>skills/sqli-payloads/data/</code>, '
                'so the same judgement produces the same requests on every '
                'run.</div>')

    body.append('<footer>Generated by the SQLi DAST agent &middot; evidence is '
                'quoted verbatim, never summarised &middot; only hosts on the '
                'configured allow-list are ever contacted.</footer></div>')

    return ("<!doctype html>\n<html lang=\"en\"><head>\n"
            "<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
            "<title>SQLi Assessment - %s</title>\n<style>%s</style>\n</head>\n"
            "<body>\n%s\n</body></html>\n"
            % (_e(target), CSS, "\n".join(body)))


def write(path, **kwargs):
    Path(path).write_text(render(**kwargs), encoding="utf-8")
    return path


if __name__ == "__main__":
    import sys
    root = Path(__file__).resolve().parent.parent
    data = json.loads((root / "artifacts" / "03_findings.json")
                      .read_text(encoding="utf-8"))
    score = None
    ev = root / "artifacts" / "06_evaluation.json"
    if ev.exists():
        score = json.loads(ev.read_text(encoding="utf-8"))
    verdicts = [dict(f, confirmed=f.get("vulnerable")) for f in data["findings"]]
    out = root / "artifacts" / "05_report.html"
    write(out, target=data["target"],
          points=[None] * data["points_total"], verdicts=verdicts,
          elapsed=data.get("elapsed_sec", 0),
          requests_used=data.get("requests_used", 0),
          score=score, mode=(score or {}).get("mode", ""))
    print("wrote %s" % out)
    sys.exit(0)
