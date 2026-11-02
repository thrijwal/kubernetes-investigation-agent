# Deployment evidence checklist

Use this checklist immediately after each GCP deployment and before deleting
temporary resources. It creates a portfolio-ready record without exposing
anything sensitive.

## Capture

- [ ] A short case-study page: problem, architecture, platform choice,
  validation, decisions, and lessons learned.
- [ ] One Console screenshot showing the deployed resource, region, and status.
- [ ] Redacted command output showing the deploy command and resulting resource
  reference or revision.
- [ ] One successful request/response or agent investigation trace.
- [ ] One operational signal, such as a redacted Cloud Logging excerpt or a
  monitoring screenshot.
- [ ] The source of truth for infrastructure: Terraform, Dockerfile, manifest,
  and deployment scripts.
- [ ] A short demo video (one to two minutes) hosted externally if it is too
  large for Git; commit a link and a small preview image instead.

## Redact before committing

Never commit any of the following:

- API keys, OAuth tokens, cookies, bearer tokens, or `.env` files;
- service-account JSON keys or private certificates;
- Terraform state or plan files containing generated secrets;
- real customer logs, personally identifiable information, or request bodies;
- private IP ranges, internal URLs, database names, or credentials;
- billing exports, account numbers, or unapproved screenshots.

## Keep the proof easy to review

- Use five to eight screenshots maximum per case study.
- Annotate each screenshot with the single claim it proves.
- Prefer reproducible configuration and redacted machine output over visual
  evidence alone.
- Use an honest title and date, such as “Deployed to Cloud Run for a hands-on
  platform comparison — 2 November 2026.”
- Link every case study from the repository README.

