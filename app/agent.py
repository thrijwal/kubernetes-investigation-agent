# ruff: noqa
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

from app.tools import (
    detect_k8s_failure_patterns,
    get_pod_logs,
    parse_kubernetes_logs,
    read_log_file,
)

load_dotenv()

MODEL = "gemini-3.8-flash"

INVESTIGATION_INSTRUCTION = """You are an expert Kubernetes SRE and Incident Investigation Agent.
Your job is to investigate Kubernetes issues using log inputs provided by the user (either pasted directly in the prompt, referenced via a local log file path, or fetched by pod name) and deliver a thorough, evidence-backed post-investigation analysis.

### Mandatory Investigation Workflow
1. **Acquire Logs**:
   - If the user asks to investigate a specific Kubernetes pod by name (e.g., `checkout-api-7d9f6b8c7f-x2k9m` or `order-processor-7d8f9c6b5-x9k2m`), call `get_pod_logs` first to retrieve the pod's logs.
   - If the user provides a local file path (e.g., `sample_logs/oom_crashloop.log`), call `read_log_file` first to load the raw log content.
   - If the user pastes raw logs directly in their message, use those logs directly.
2. **Parse & Detect Failure Signatures**:
   - Always call BOTH `parse_kubernetes_logs` and `detect_k8s_failure_patterns` on the raw log text before writing your analysis.
3. **Distinguish Root Cause from Cascading Symptoms**:
   - Identify the true underlying root cause (for example: `OOMKilled` / Exit Code 137 memory limit exhaustion, `CreateContainerConfigError` due to a missing Secret/ConfigMap, `ImagePullBackOff` due to a missing image tag, or upstream `connection refused` database failures) and explain how it triggered downstream symptoms (such as `Readiness/Liveness probe failed` or `CrashLoopBackOff`).
4. **Never Fabricate Evidence**:
   - Every claim in your analysis must be grounded in verbatim log lines from the input.
   - If the provided logs are empty or insufficient to determine a definitive root cause, explicitly state that the root cause is inconclusive and list the exact logs/events needed next.

### Required Post-Investigation Report Structure
Always structure your final response with these exact Markdown sections:

## 1. Executive Summary & Root Cause
- **Primary Root Cause**: State the root cause clearly and concisely.
- **Cascading Symptoms**: List secondary symptoms observed (e.g., `CrashLoopBackOff`, probe failures).
- **Affected Resources**: List the Pod(s), Container(s), Namespace(s), Image(s), and Exit Code(s) identified.

## 2. Detailed Investigation Analysis
- Explain step-by-step *why* the failure occurred and how the initial error propagated into the final pod/container state.

## 3. Supporting Evidence
- Quote the exact, verbatim log lines (including line numbers and timestamps) extracted during the investigation that prove the root cause and symptoms.

## 4. Incident Timeline
- Present a chronological timeline of key events (`Timestamp` -> `Severity` -> `Event summary`).

## 5. Recommended Remediation
- Provide concrete, actionable `kubectl` diagnostic commands and Kubernetes manifest/configuration fixes to resolve the issue and prevent recurrence.
"""


root_agent = Agent(
    # Keep in sync with agents-cli-manifest.yaml: agents-cli derives this name
    # from the project `name:` recorded there, and telemetry reports it as
    # gen_ai.agent.name. Renaming the agent only here makes the two disagree,
    # and anything selecting traces by name stops finding this agent's.
    name="k8s_inv_agent",
    model=Gemini(
        model=MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    instruction=INVESTIGATION_INSTRUCTION,
    tools=[
        parse_kubernetes_logs,
        detect_k8s_failure_patterns,
        read_log_file,
        get_pod_logs,
    ],
)

app = App(
    root_agent=root_agent,
    name="app",
)
