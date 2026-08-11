import html
import json
import time
import urllib.parse
from pathlib import Path
from typing import Optional, Type

from deepagents import create_deep_agent
from dotenv import load_dotenv
from langchain.tools import BaseTool
from langchain_aws import ChatBedrockConverse
from langchain_core.callbacks.manager import CallbackManagerForToolRun
from playwright.sync_api import sync_playwright
from pydantic import BaseModel, Field

load_dotenv()

SCREENSHOT_DIR = Path(__file__).parent / "steps"
SCREENSHOT_DIR.mkdir(exist_ok=True)


class BrowserInput(BaseModel):
    req: str = Field(
        description="data to send with the request, example: {'url': 'http://example.com/path', 'method': 'GET', 'data': {}}"
    )


class BrowserTool(BaseTool):
    name: str = "browser_tool"
    description: str = (
        "Useful for when you need to load a url in a real browser to check for XSS. "
        "Renders the response and executes any JavaScript in it, so a triggered "
        "alert()/confirm()/prompt() popup confirms the payload actually fired. "
        "Can be used for GET and POST requests."
    )
    args_schema: Type[BrowserInput] = BrowserInput

    def _run(
        self, req: str, run_manager: Optional[CallbackManagerForToolRun] = None
    ) -> str:
        """Use the tool."""
        data = json.loads(req)
        url = data["url"]
        method = data.get("method", "GET").upper()
        params = data.get("data") or {}
        print(
            f"Loading {method} {url} in browser with data: {params if params else 'N/A'}"
        )

        dialogs = []

        def handle_dialog(dialog):
            dialogs.append({"type": dialog.type, "message": dialog.message})
            print(f"XSS popup triggered! [{dialog.type}] {dialog.message}")
            # Pause briefly so the popup is visible in the browser window before it is dismissed.
            time.sleep(2)
            dialog.accept()

        screenshot_path = None
        body = ""
        status = None

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=False, slow_mo=250)
                page = browser.new_page()
                page.on("dialog", handle_dialog)

                try:
                    if method == "POST":
                        # Navigate the browser to a real HTML form that POSTs to the target
                        # so the server response is rendered (and any XSS payload executes)
                        # exactly as it would for a victim submitting the form.
                        inputs = "".join(
                            f'<input type="hidden" name="{html.escape(str(k))}" value="{html.escape(str(v))}">'
                            for k, v in params.items()
                        )
                        form_html = (
                            f'<html><body><form id="xss-form" method="POST" action="{html.escape(url)}">'
                            f"{inputs}</form>"
                            "<script>document.getElementById('xss-form').submit();</script>"
                            "</body></html>"
                        )
                        page.set_content(form_html)
                        page.wait_for_load_state("networkidle", timeout=15000)
                    else:
                        query = urllib.parse.urlencode(params)
                        full_url = f"{url}?{query}" if query else url
                        response = page.goto(
                            full_url, wait_until="networkidle", timeout=15000
                        )
                        status = response.status if response else None

                    page.wait_for_timeout(1000)
                    body = page.content()
                except Exception as nav_error:
                    body = f"Navigation error: {nav_error}"

                screenshot_path = str(
                    SCREENSHOT_DIR / f"xss_{int(time.time() * 1000)}.png"
                )
                page.screenshot(path=screenshot_path, full_page=True)
                browser.close()
        except Exception as e:
            return f"Browser request failed: {str(e)}"

        result = {
            "url": url,
            "method": method,
            "status_code": status,
            "popup_triggered": bool(dialogs),
            "popups": dialogs,
            "screenshot": screenshot_path,
            "body_snippet": body[:3000],
        }
        return json.dumps(result)

    async def _arun(
        self, req: str, run_manager: Optional[CallbackManagerForToolRun] = None
    ) -> str:
        raise NotImplementedError("browser_tool does not support async")


# Define tools and LLMs.
tools = [BrowserTool()]
orchestrator_llm = ChatBedrockConverse(
    # model_id="qwen.qwen3-coder-30b-a3b-v1:0",
    model_id="us.anthropic.claude-haiku-4-5-20251001-v1:0",
    temperature=0.6,
)
subagent_llm = ChatBedrockConverse(
    model_id="qwen.qwen3-coder-30b-a3b-v1:0",
    temperature=0.6,
)

# Subagent that actually fires a single payload at a single injection point.
payload_tester_prompt = """You are given ONE candidate injection point (a URL, HTTP method, and
parameter set) and ONE specific XSS payload already substituted into that parameter set.

### Task
1. Load the request in the browser tool exactly as given (do not modify the payload).
2. Inspect the tool result:
   - popup_triggered / popups: whether a JavaScript dialog actually fired (the strongest evidence of XSS)
   - body_snippet: whether the payload is reflected unescaped even if no popup fired
   - screenshot: path to a screenshot of the page at the time it was rendered
3. Report back ONLY on this single payload/injection point.

### Output Format
- URL: (str)
- Parameter: (str) the parameter that carried the payload
- Payload: (str) the exact payload tested
- XSS: (str) Yes or No
- Evidence: (str) "popup" or "reflected-in-body" or "none"
- Justification: (str) brief justification ONLY if XSS is confirmed
"""

subagents = [
    # {
    #     "name": "xss-payload-tester",
    #     "description": (
    #         "Tests one specific XSS payload against one specific URL/parameter combination "
    #         "using a real browser, and reports whether it triggered a popup or was reflected "
    #         "unescaped. Delegate each candidate payload/injection-point pair to a separate "
    #         "call of this subagent so payloads are tested independently."
    #     ),
    #     "system_prompt": payload_tester_prompt,
    #     "tools": [BrowserTool()],
    #     "model": subagent_llm,
    # },
    {
        "name": "dom-based-payload-tester",
        "description": "Sends an HTTP request (GET or POST) to a given URL and analyzes the response headers and body for JavaScript that reflects user-controlled input in a way that could enable DOM-based XSS. Uses multi-step reasoning to identify vulnerable scripts, explain why each is exploitable, and suggest candidate attack strings per parameter. Use this agent when you need to assess a single URL/endpoint for DOM-based cross-site scripting risk. Input: a target URL and HTTP method. Output: structured findings with URL, vulnerable JavaScript, justification, and attack strings.",
        "system_prompt": Path("scripts/exercise-09/xss-prompts/dom-based.txt").read_text(encoding="utf-8"),
        "tools": [BrowserTool()],
        "model": subagent_llm,
    },
    {
        "name": "reflected-xss-payload-tester",
        "description": "Sends an HTTP request (GET or POST) to a given URL and tests all available request parameters with simple and advanced payloads to determine if any are vulnerable to reflected cross-site scripting, analyzing the response headers and body for reflected input. Uses multi-step reasoning to identify vulnerable parameters, explain why each is exploitable, and suggest candidate attack strings per parameter. Use this agent when you need to assess a single URL/endpoint for reflected XSS risk. Input: a target URL and HTTP method. Output: structured findings with URL, analyzed parameters, vulnerable parameters, justification, and attack strings.",
        "system_prompt": Path("scripts/exercise-09/xss-prompts/reflected-xss.txt").read_text(encoding="utf-8"),
        "tools": [BrowserTool()],
        "model": subagent_llm,
    },
]

# System prompt
system_prompt = """You are a security expert that checks whether a page is vulnerable to cross-site scripting (Reflected, Stored, or DOM-based) using a multi-step reasoning process.

### Analysis Process
1. **Recon**: Load the provided URL yourself with the browser tool (GET or POST as specified) to see the page, its parameters, and any inline JavaScript.
2. **Craft Candidates**: Based on that recon, identify candidate injection points (parameters, headers, etc.) and craft one or more XSS payloads to test against each.
3. **Delegate**: For EACH (injection point, payload) pair, delegate to the `xss-payload-tester` subagent via the `task` tool, passing the exact URL/method/parameters (with the payload substituted in) for it to test. Do this for every candidate — do not test payloads yourself once you have candidates to delegate.
4. **Aggregate**: Collect the results from all delegated subagent calls and combine them into a single final answer.

You have access to a browser tool that loads a URL in a real, visible browser and executes its JavaScript, and a `task` tool for delegating individual payload tests to the `xss-payload-tester` subagent.

### Output Format
Your final response must include, for each injection point/payload tested:
- URL: (str) The URL of the request
- Parameters: (str) The parameters sent with the request
- XSS: (str) Any identified XSS vulnerabilities (Yes or No)
- Justification: (str) A brief justification ONLY if XSS is confirmed, noting whether it was confirmed via a triggered popup or via reflected payload in the response body
"""

# Create DeepAgent
agent = create_deep_agent(
    model=orchestrator_llm,
    tools=tools,
    subagents=subagents,
    system_prompt=system_prompt,
)


def run_agent(url: str) -> dict:
    """
    Analyze the given URL using the agent and return the result.
    """
    response = agent.invoke({"messages": [{"role": "user", "content": url}]})
    return response


if __name__ == "__main__":
    # Example input for POST request
    url = "https://vtm.rdpt.dev/taskManager/login/"
    method = "POST"
    data = {"username": "admin", "password": "admin"}
    post_input = f"Test this endpoint for XSS: URL={url}, Method={method}, Data={data}"

    result = agent.invoke({"messages": [{"role": "user", "content": post_input}]})
    print(result["messages"][-1].content)
