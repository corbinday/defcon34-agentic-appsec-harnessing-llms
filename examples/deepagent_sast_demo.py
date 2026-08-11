from posix import system

from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langchain_aws import ChatBedrockConverse
from langchain_core.runnables import RunnableLambda
from fetch_url_tool import FetchURLTool
from dotenv import load_dotenv
import os
import git


load_dotenv()

# Git repo setup
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
repo_url = "https://github.com/redpointsec/vtm.git"
repo_path = os.path.join(SCRIPT_DIR, "repo")

if os.path.isdir(repo_path) and os.path.isdir(os.path.join(repo_path, ".git")):
    print("Directory already contains a git repository.")
else:
    try:
        repo = git.Repo.clone_from(repo_url, repo_path)
        print(f"Repository cloned into: {repo_path}")
    except Exception as e:
        print(f"An error occurred while cloning the repository: {e}")

# LLM setup
llm = ChatBedrockConverse(
    model_id="qwen.qwen3-coder-30b-a3b-v1:0",
    temperature=0.6,
)

# Backend for local filesystem access - points to the repo directory
filesystem_backend = FilesystemBackend(root_dir=repo_path, virtual_mode=False)

# Skills setup — loaded into each agent's context as domain expertise
skills_dir = os.path.join(SCRIPT_DIR, "skills")

print(f"Repo path: {repo_path}")
print(f"Skills directory: {skills_dir}")
for skill_name in os.listdir(skills_dir):
    skill_path = os.path.join(skills_dir, skill_name, "SKILL.md")
    if os.path.exists(skill_path):
        print(f"  - {skill_name}")

# --- Prompt 1: Context Collection ---
prompt_collect_context = """You are a security engineer performing reconnaissance on a Python/Django codebase.
Your ONLY job is to collect and organize code context relevant to access control.
Do NOT perform any security analysis yet. Just gather the facts.

### What to Collect
1. **Routing & URL configuration** — Find all URL config files (urls.py). List every route and the view it maps to.
2. **Views & API endpoints** — Read every view function and class-based view. Note which ones have authentication/authorization decorators and which do NOT.
3. **Middleware** — Find and read all middleware classes, especially anything related to auth, sessions, or permissions.
4. **Models with ownership** — Identify models that have a user/owner foreign key or any field that ties data to a specific user.
5. **Permission classes & decorators** — Find all custom permission checks, decorators (login_required, permission_required, user_passes_test), and mixins (LoginRequiredMixin, PermissionRequiredMixin, etc.).
6. **Direct object lookups** — Find places where objects are fetched by ID from request parameters (GET/POST params, URL kwargs) without verifying the requesting user owns or has access to that object.

### Output Format
Produce a structured inventory in markdown:
- For each view/endpoint: the route, the view, what auth/authz is applied (or "NONE"), and whether it does object-level ownership checks.
- For each model with ownership: the model name, the ownership field, and which views query it.
- List any middleware that enforces access control globally.

Do NOT make security judgments. Just collect the raw facts.
"""

# --- Prompt 2: Analysis & Review Plan ---
prompt_analysis_plan = """You are a security engineer analyzing a Python/Django codebase for
OWASP 2025 A01: Broken Access Control vulnerabilities.

You have already collected a context inventory of the codebase (routes, views, models,
middleware, permissions). Your job is to build an **adaptive review plan** — not a static
checklist. Use the context inventory to decide which checks are relevant and which are not.

### Step 1: Triage the Context

Before running any checks, read the context inventory and answer these questions:
- Does the app use Django REST Framework, plain Django views, or both?
- Are there API endpoints that return JSON, or only template-rendered HTML views?
- Is there global authentication middleware, or is auth enforced per-view?
- Are there models with user/owner foreign keys?
- Does the app have an admin interface or admin-only views?
- Is there any CORS configuration (django-cors-headers, custom middleware)?
- Does the app use sequential integer PKs or UUIDs for sensitive models?

Use your answers to ADD relevant checks and REMOVE irrelevant ones below.

### Step 2: Run Each Discrete Check

Evaluate each sub-category independently. For each one, determine if it applies to this
codebase based on the context, then either run the check or mark it as NOT_APPLICABLE.

#### Check 1: Missing Authentication (CWE-862)
Views/endpoints that should require login but do not have @login_required,
LoginRequiredMixin, or permissions.IsAuthenticated.
- SKIP IF: Global auth middleware forces login on all views.
- ADD IF: The app mixes public and private views without a clear pattern.

#### Check 2: Insecure Direct Object References / IDOR (CWE-639)
Objects fetched by user-supplied ID (URL kwargs, GET/POST params) without verifying the
requesting user owns or has access to that object.
- SKIP IF: All querysets are globally filtered by request.user with no pk lookups.
- ADD IF: Models have owner/user FKs and views do .get(pk=id) without ownership filtering.

#### Check 3: Privilege Escalation (CWE-269)
Endpoints where a regular user could perform admin-only actions, or an unauthenticated
user could act as authenticated.
- SKIP IF: There are no admin-only or role-gated views in the app.
- ADD IF: There are views that check is_staff/is_superuser or use group-based permissions.

#### Check 4: Missing Function-Level Access Control (CWE-285)
POST/PUT/DELETE operations that lack authorization checks even when the corresponding
GET endpoint is protected.
- SKIP IF: All state-changing views have the same decorators as their read counterparts.
- ADD IF: Views handle multiple HTTP methods and only check auth on GET.

#### Check 5: Parameter Tampering
Request parameters (URL params, form fields, JSON body) used to set ownership or access
another user's resources without server-side validation. For example, a hidden form field
for user_id that the server trusts instead of using request.user.
- SKIP IF: All ownership is derived from request.user / auth token.
- ADD IF: Create/update views accept a user or owner field from client input.

#### Check 6: CORS Misconfiguration
Overly permissive Access-Control-Allow-Origin settings that could allow unauthorized
cross-origin API access.
- SKIP IF: The app has no API endpoints, or no CORS configuration exists (same-origin only).
- ADD IF: django-cors-headers is installed or custom CORS middleware/headers are present.

#### Check 7: Forced Browsing
Admin or restricted pages accessible by guessing or manipulating URLs without proper
server-side authorization checks.
- SKIP IF: There are no admin-only URL patterns or all are behind auth middleware.
- ADD IF: There are URL patterns like /admin/, /manage/, /dashboard/ that rely on
  obscurity rather than access control.

#### Check 8: Default-Allow Posture
Access is granted by default rather than denied by default. The app should require explicit
grants rather than assuming access is allowed unless denied.
- SKIP IF: Global middleware enforces deny-by-default.
- ADD IF: New views are accessible by default and auth is opt-in via decorators.

#### Additional Checks (Add Based on Context)
If the context inventory reveals patterns not covered above, add new checks. Examples:
- If DRF is used: check for missing or misconfigured DEFAULT_PERMISSION_CLASSES in settings.
- If the app uses Django groups: check if group membership is verified before privileged ops.
- If there are file upload/download views: check if file access is gated by ownership.
- If the app has API token auth: check if tokens are scoped appropriately.

### Step 3: Output Format

Produce a review plan in JSON with each check as its own section:
```json
{{
  "context_summary": "2-3 sentences summarizing what the app does and how auth works",
  "checks": [
    {{
      "check_id": "check_1_missing_auth",
      "name": "Missing Authentication",
      "cwe": "CWE-862",
      "status": "APPLICABLE | NOT_APPLICABLE",
      "reason_for_status": "Why this check applies or does not apply to this codebase",
      "findings": [
        {{
          "file": "file path",
          "location": "function/class name and line range",
          "observation": "What you observed in the code",
          "severity": "critical | high | medium | low",
          "confidence": "high | medium | low",
          "needs_validation": "What specifically should be verified in the next step"
        }}
      ]
    }}
  ],
  "additional_checks": [
    {{
      "check_id": "descriptive_id",
      "name": "Name of the check",
      "cwe": "CWE number if applicable",
      "reason_added": "Why this check was added based on the context",
      "findings": []
    }}
  ]
}}
```

Be specific. Cite exact file paths, function names, and line numbers.
Do NOT pad findings — only report patterns you actually see evidence for.
If a check is NOT_APPLICABLE, its findings array should be empty.
"""

# --- Prompt 3: Review & Validation ---
prompt_review_validate = """You are a senior security engineer performing final validation
of potential OWASP 2025 A01: Broken Access Control findings in a Python/Django codebase.

You have a list of suspected findings from a prior analysis. For EACH finding, you must:

### Validation Steps
1. **Re-read the code** — Go back to the exact file and location cited. Read the full function/class, not just a snippet.
2. **Trace the full request path** — Follow the request from URL routing through middleware, through the view, to the database query. Check if access control is enforced at ANY layer (middleware, decorator, view logic, queryset filtering).
3. **Check for indirect protections** — Is there global middleware that enforces auth? Does the queryset filter by the current user even without an explicit check? Is the view behind a protected URL namespace?
4. **Challenge the finding** — Ask: "Could an attacker actually exploit this?" If the answer is no because of a protection you missed, downgrade or dismiss the finding.
5. **Confirm or reject** — Mark each finding as CONFIRMED, DOWNGRADED, or FALSE_POSITIVE with an explanation.

### Output Format
Produce a final report in JSON:
```json
{{
  "validated_findings": [
    {{
      "original_finding": "Brief description from the analysis plan",
      "status": "CONFIRMED | DOWNGRADED | FALSE_POSITIVE",
      "evidence": "The specific code/logic that confirms or refutes the finding",
      "exploit_scenario": "If CONFIRMED: how an attacker would exploit this, step by step",
      "remediation": "If CONFIRMED: specific code change recommended",
      "severity": "critical | high | medium | low | informational"
    }}
  ],
  "overall_assessment": {{
    "total_confirmed": 0,
    "total_downgraded": 0,
    "total_false_positives": 0,
    "risk_rating": "critical | high | medium | low",
    "summary": "2-3 sentence summary of the access control posture"
  }}
}}
```

Be ruthless about false positives. A finding with no realistic exploit path is not a finding.
"""


# ------------------------------------------------------------------------------
# Step Factory (follows audit.py LCEL pattern)
# ------------------------------------------------------------------------------
def new_step(name: str, system_prompt: str):
    agent = create_deep_agent(
        model=llm,
        tools=[FetchURLTool()],
        backend=filesystem_backend,
        system_prompt=system_prompt,
        skills=[skills_dir],
    )

    def _run_step(input_text: str) -> str:
        print(f"\n[{name.upper()} STEP INPUT]\n", input_text)
        print(f"\n[{name.upper()}] Running (streaming)...")

        final_output = ""
        tool_calls_made = []

        try:
            for event in agent.stream(
                {"messages": [{"role": "user", "content": input_text}]}
            ):
                for key, value in event.items():
                    if "Middleware" in key:
                        continue
                    if isinstance(value, dict) and "messages" in value:
                        for msg in value["messages"]:
                            if hasattr(msg, "tool_calls") and msg.tool_calls:
                                for tc in msg.tool_calls:
                                    tool_calls_made.append(tc["name"])
                                    print(f"  -> {tc['name']}")
                            elif hasattr(msg, "content") and msg.content:
                                final_output = msg.content

        except Exception as e:
            error_type = type(e).__name__
            print(f"\n[{name.upper()}] ERROR: {error_type}")
            print(f"  Message: {str(e)[:200]}...")
            print(f"  Tools called before error: {tool_calls_made}")

            if not final_output:
                final_output = (
                    f"[TIMEOUT ERROR]\n"
                    f"The agent timed out before completing.\n"
                    f"Tools called: {', '.join(tool_calls_made) or 'none'}\n"
                )

        print(f"\n[{name.upper()} STEP RESULT]\n", final_output)

        steps_dir = os.path.join(SCRIPT_DIR, "steps")
        os.makedirs(steps_dir, exist_ok=True)
        with open(os.path.join(steps_dir, f"{name}.txt"), "w") as fh:
            fh.write(final_output)

        return final_output

    return RunnableLambda(_run_step)

# ------------------------------------------------------------------------------
# Custom Steps
# ------------------------------------------------------------------------------
prompt_generate_report = """
You are a security engineer creating a report for executive leadership on the findings from the previous steps.
You have the data, you've analyzed it. Now, frame the overall posture in the context of business risk.
Your final output should be markdown. Do not include any commentary outside of the output.
"""

# ------------------------------------------------------------------------------
# LCEL Chain — Context Collection | Analysis Plan | Review & Validation
# ------------------------------------------------------------------------------
collect_step = new_step(name="collect_context", system_prompt=prompt_collect_context)
analyze_step = new_step(name="analysis_plan", system_prompt=prompt_analysis_plan)
validate_step = new_step(name="review_validate", system_prompt=prompt_review_validate)
report_step = new_step(name="generate_report", system_prompt=prompt_generate_report)

full_chain = (
    RunnableLambda(lambda task: task)
    | collect_step
    | analyze_step
    | validate_step
    | report_step
)


if __name__ == "__main__":
    print("DeepAgent SAST Demo — A01:2025 Broken Access Control")
    print("=" * 60)

    full_chain.invoke(
        "Explore the codebase and collect a full access control inventory. "
        "Start with the directory structure, then read all relevant files."
    )
