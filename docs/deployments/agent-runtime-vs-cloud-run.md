# What I learned: Agent Runtime vs. Cloud Run

I deployed the Kubernetes Investigation Agent to both Google Cloud Agent Runtime
and Cloud Run to compare a managed agent-native platform with a container-based
service deployment.

## The shared system

Both deployments use the same core implementation:

- Google ADK agent and investigation instructions;
- deterministic Kubernetes log parsing and failure detection tools;
- FastAPI/A2A application interface;
- Docker and dependency configuration;
- Terraform deployment source; and
- incident samples and evaluation scenarios.

This meant the comparison was about platform responsibilities, not two
unrelated applications.

## Platform trade-offs

### Agent Runtime

**Best fit:** an agent-first product that primarily follows the ADK runtime and
its managed deployment workflow.

- The deployment model is aligned with an ADK agent lifecycle.
- It reduces the amount of service/container platform work required for a
  learning project.
- It lets the engineer focus on agent instructions, tools, evaluation, and
  observability.

### Cloud Run

**Best fit:** a containerized HTTP service that needs deliberate control over
its runtime, ingress, network configuration, or service behavior.

- The service boundary is explicit through the Dockerfile and FastAPI app.
- Scaling, concurrency, identity, VPC access, and container configuration are
  infrastructure decisions captured in Terraform.
- It provides flexibility, while requiring the engineer to own more operational
  choices.

## Practical conclusion

For a primarily ADK-based agent, Agent Runtime is the simpler path to validate
agent behavior quickly. For a service that needs custom HTTP behavior or finer
control of the container platform, Cloud Run is a strong fit.

Learning both was valuable: it demonstrated that the agent can be operated as
either a managed agent deployment or a containerized service, and made the
infrastructure trade-offs visible in source control.

## Evidence map

- [Agent Runtime deployment record](2026-11-02-agent-runtime.md)
- [Cloud Run deployment record](2026-11-02-cloud-run.md)
- [Terraform configuration](../../deployment/terraform/single-project/)
- [Deployment metadata](../../deployment_metadata.json)
- [Evaluation dataset](../../tests/eval/datasets/basic-dataset.json)
- [Evidence capture and redaction checklist](evidence-checklist.md)

