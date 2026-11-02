# Deployment record: Google Cloud Agent Runtime

**Date:** 2 November 2026  
**Platform:** Google Cloud Agent Runtime  
**Region:** `us-east1`  
**Agent:** Kubernetes Investigation Agent (`k8s_inv_agent`)  
**Status:** Deployed and validated by the author

## Objective

Deploy an ADK-based SRE assistant that analyzes Kubernetes logs, separates root
causes from cascading symptoms, and returns an evidence-backed remediation
report. The exercise focused on using a managed, agent-native Google Cloud
deployment target.

## What was deployed

- A Python Google ADK agent with a FastAPI/A2A interface.
- Deterministic tools for reading logs, parsing Kubernetes events, and detecting
  common failure signatures such as OOM kills, bad image references, missing
  configuration, probe failures, scheduling pressure, and upstream failures.
- Evaluation data and quality criteria for known incident scenarios.
- Infrastructure and deployment configuration tracked in this repository.

The deployment metadata recorded at deployment time is versioned in
[`deployment_metadata.json`](../../deployment_metadata.json). It identifies the
deployed Agent Runtime resource, target, timestamp, region, and agent directory.

## Architecture

```text
User / A2A client
       |
       v
Google Cloud Agent Runtime
       |
       v
Google ADK agent (k8s_inv_agent)
       |
       +-- read log files or request Kubernetes pod logs
       +-- parse Kubernetes events and log timeline
       +-- detect known failure signatures
       |
       v
Evidence-backed incident report
```

## Validation approach

The agent was validated using representative incident inputs included in
[`sample_logs/`](../../sample_logs/) and the evaluation dataset in
[`tests/eval/datasets/basic-dataset.json`](../../tests/eval/datasets/basic-dataset.json).

The expected behavior is that the agent:

1. obtains or reads the incident logs;
2. parses the logs and detects failure patterns in the same investigation turn;
3. quotes supporting evidence rather than inventing claims; and
4. returns a concise root cause, timeline, and concrete remediation steps.

## Why Agent Runtime

Agent Runtime was used to learn the managed deployment path for an ADK agent.
It keeps the project close to the agent framework's deployment and evaluation
workflow, allowing the work to focus on agent behavior, evidence quality, and
observability rather than container platform operations.

## Evidence and safety

No credentials, tokens, Terraform state, customer data, or unredacted
production logs are stored in this repository. See the
[evidence checklist](evidence-checklist.md) for the artifacts that should be
captured before the cloud resources are removed.

## What I learned

- A managed agent-native runtime is useful when the core product is an ADK agent.
- Deterministic log-analysis tools keep investigation conclusions grounded.
- Evaluation cases are required alongside a successful manual prompt; they make
  the expected incident-analysis behavior explicit and repeatable.

