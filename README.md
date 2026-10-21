# Kubernetes Investigation Agent

An AI SRE assistant that investigates Kubernetes failures from logs and writes an evidence-backed root-cause report.

You can feed it logs in three ways:

1. Paste raw logs into the chat.
2. Point it at a local file (for example `sample_logs/oom_crashloop.log`).
3. Ask it to investigate a pod by name. It tries `kubectl logs` first, then falls back to matching files in `sample_logs/` if no cluster is reachable.

The agent does **not** change your cluster. It only reads logs, matches known failure signatures, and explains what went wrong.

Built with [Google ADK](https://adk.dev/) and generated with `agents-cli` 1.10.0.

---

## What problem this solves

When a pod is in `CrashLoopBackOff`, that name is usually a **symptom**, not the cause. The real issue might be:

- the container ran out of memory (`OOMKilled`, exit 137)
- a Secret or ConfigMap is missing (`CreateContainerConfigError`)
- the image tag does not exist (`ImagePullBackOff`)
- a database or DNS dependency is down
- a liveness probe is failing because of one of the above

This agent is written to separate **root cause** from **cascading symptoms**, quote the exact log lines that prove it, and suggest concrete `kubectl` / manifest fixes.

---

## How it works

```text
You (paste logs / file path / pod name)
        |
        v
  Gemini (k8s_inv_agent)
        |
        +-- get_pod_logs            fetch live kubectl logs, or sample_logs fallback
        +-- read_log_file           load a workspace .log / .txt / .json / .out file
        +-- parse_kubernetes_logs   timestamps, severity, pods, namespaces, exit codes, timeline
        +-- detect_k8s_failure_patterns   match known K8s failure signatures
        |
        v
  Structured investigation report
```

The model is instructed to always:

1. Acquire logs (pod, file, or pasted text).
2. Call **both** `parse_kubernetes_logs` and `detect_k8s_failure_patterns` before writing analysis.
3. Ground every claim in verbatim log lines.
4. Say the root cause is **inconclusive** if the logs are healthy or too thin.

The final answer always uses these sections:

1. Executive Summary & Root Cause
2. Detailed Investigation Analysis
3. Supporting Evidence
4. Incident Timeline
5. Recommended Remediation

---

## Project layout

```text
kubernetes-investigation-agent/
├── app/
│   ├── agent.py                 # Agent definition, model, investigation playbook
│   ├── tools.py                 # Log parsing, failure signatures, file + kubectl tools
│   ├── fast_api_app.py          # Local HTTP / playground server
│   └── app_utils/               # Sessions, A2A, Cloud console adapters
├── sample_logs/                 # Practice incidents for local testing
├── tests/
│   ├── unit/                    # Tests for the Python tools
│   ├── integration/             # Server / agent smoke tests
│   └── eval/                    # Eval dataset and grading metrics
├── agents-cli-manifest.yaml     # agents-cli project identity
├── GEMINI.md                    # Guide for AI-assisted development
└── pyproject.toml               # Dependencies
```

The code you will usually edit is:

| File | What it contains |
|---|---|
| `app/agent.py` | Model name, system instruction, which tools the agent may call |
| `app/tools.py` | Deterministic log parsing and Kubernetes failure regex catalog |

---

## Tools

| Tool | Purpose |
|---|---|
| `get_pod_logs` | Run `kubectl logs <pod> -n <ns>`. If kubectl is missing or the cluster is unreachable, search `sample_logs/` for that pod name. |
| `read_log_file` | Read a log file inside this project. Blocks path traversal and secret files (`.env`, credentials). |
| `parse_kubernetes_logs` | Split logs into a timeline, severity counts, and extracted entities (pods, namespaces, containers, images, exit codes). |
| `detect_k8s_failure_patterns` | Scan logs against known signatures and return root-cause suspects vs symptoms, plus quoted evidence. |

Failure signatures currently detected:

- OOMKilled / memory exhaustion
- Missing Secret or ConfigMap
- ImagePullBackOff / ErrImagePull
- Upstream network, DNS, or database failures
- Liveness / readiness / startup probe failures *(symptom)*
- RBAC or filesystem permission errors
- Volume / PVC / disk exhaustion
- Scheduling failure, node pressure, eviction
- Application crash / unhandled exception
- CrashLoopBackOff *(symptom)*

---

## Requirements

- **uv** — [install](https://docs.astral.sh/uv/getting-started/installation/)
- **agents-cli** — `uv tool install google-agents-cli`
- **Google Cloud SDK** (for Gemini / GCP) — [install](https://cloud.google.com/sdk/docs/install)
- **kubectl** (optional) — only needed if you want live cluster logs. Without it, the agent uses `sample_logs/`.

---

## Quick start

```bash
uvx google-agents-cli setup
agents-cli install
agents-cli playground
```

The playground starts a local web UI and reloads when you edit `app/agent.py` or `app/tools.py`.

You can also use the [ADK](https://adk.dev/) CLI with `uv run adk`.

### Try these prompts

```text
Investigate sample_logs/oom_crashloop.log

Investigate the Kubernetes incident in sample_logs/payment_service_probe_failure.log

Investigate pod checkout-api-7d9f6b8c7f-x2k9m in namespace production
```

Or paste raw `kubectl logs` / `kubectl describe` output directly into the chat.

Sample incidents in this repo:

| File | What it demonstrates |
|---|---|
| `sample_logs/oom_crashloop.log` | Memory limit hit, OOMKilled, then CrashLoopBackOff |
| `sample_logs/payment_service_probe_failure.log` | Database connection refused causing probe failures |
| `sample_logs/image_pull_and_config_error.log` | Bad image tag plus a missing Secret |

---

## Tests and evaluation

```bash
uv run pytest tests/unit tests/integration
agents-cli lint
agents-cli eval run
```

Eval cases live in `tests/eval/datasets/basic-dataset.json`. Grading checks:

- the agent used both parse and detect tools
- the report includes root cause, evidence, timeline, and remediation
- the written analysis matches the expected incident (LLM-as-judge)

---

## Commands

| Command | Description |
|---|---|
| `agents-cli install` | Install Python dependencies with uv |
| `agents-cli playground` | Local web UI for chatting with the agent |
| `agents-cli lint` | Code quality checks |
| `agents-cli eval` | Run / grade / analyze agent evaluations |
| `uv run pytest tests/unit tests/integration` | Unit and integration tests |
| `agents-cli deploy` | Deploy to Agent Runtime |
| `agents-cli publish gemini` | Register a deployed agent with Gemini |

Project management (optional):

| Command | What it does |
|---|---|
| `agents-cli scaffold enhance` | Add CI/CD and Terraform |
| `agents-cli infra cicd` | Set up the full pipeline and infrastructure |
| `agents-cli scaffold upgrade` | Upgrade the scaffold while keeping your custom code |

---

## Deployment

```bash
gcloud config set project <your-project-id>
agents-cli deploy
```

Telemetry can export to Cloud Trace, BigQuery, and Cloud Logging.

This agent also speaks the [A2A Protocol](https://a2a-protocol.org/). Use the [A2A Inspector](https://github.com/a2aproject/a2a-inspector) to test interoperability.

---

## Development notes

- Keep `root_agent.name` in `app/agent.py` in sync with `agents-cli-manifest.yaml` (`k8s_inv_agent`). Telemetry uses that name.
- Do not change the model unless you intend to. Location 404s are usually a `GOOGLE_CLOUD_LOCATION` issue, not a model-name issue.
- `get_pod_logs` validates pod / namespace / container names before calling kubectl, and times out after 8 seconds.
- AI-assisted workflow details are in `GEMINI.md`.
