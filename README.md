# postman-cse-payment-accelerator

Enterprise-ready automation for converting OpenAPI specifications into governed, runnable Postman workspaces using CI.

This project demonstrates a repeatable **Customer Solutions Engineering pattern** for reducing API onboarding friction, improving trust, and scaling Postman usage across large teams.

---

## Problem

In many organizations, APIs are defined in OpenAPI specs but Postman onboarding remains manual:

- Engineers hand-create collections and environments
- Authentication setup is tribal knowledge
- Workspaces drift over time
- Re-onboarding repeats the same work for every API

This creates slow time-to-first-call, inconsistent setups, and low confidence in API correctness.

---

## Solution Overview

This project implements an automated ingestion pipeline that:

- Treats the OpenAPI spec in version control as the **source of truth**
- Uses CI to generate or update Postman collections idempotently
- Injects standardized environments and pre-request auth logic
- Produces audit logs for governance and traceability

The result: engineers can run valid API workflows in Postman **within seconds**, with zero manual setup.

---

## High-Level Architecture

OpenAPI Spec (GitHub)  
→ CI Sync (GitHub Actions or local script)  
→ Postman Spec Hub (single source of truth)  
→ Auto-generated Collections + Standard Environments  
→ Governed, discoverable workspaces ready for use

---

## Business Value

**Outcomes**
- Faster onboarding for API consumers and testers
- Elimination of manual Postman setup steps
- Consistent auth, variables, and naming across environments
- Reduced drift via idempotent sync and spec hashing

**Operational benefits**
- Repeatable onboarding pattern for every API
- Clear ownership via PR-driven spec changes
- Auditable changes via JSON-lines action logs

---

## ROI Calculation (Illustrative)

Per-API assumptions:
- Manual setup time: 2 hours
- Automated setup time: 0.25 hours
- Developer cost: $60/hour

Savings per API:
- Manual: $120
- Automated: $15
- Net savings: **$105 per API**

For 46 APIs:
- Manual cost: $5,520
- Automated cost: $690
- Net savings: **$4,830**

> Note: This per-API example complements the team-level ROI shown in the accompanying presentation.

This calculation excludes downstream savings from reduced rework, fewer support escalations, and improved API reliability across environments.


---

## Scaling Strategy

This pattern scales across dozens of APIs and teams by:

1. Standardizing OpenAPI specs (required `info`, tags, versioning)
2. Maintaining a mapping file for API → workspace → environments
3. Running ingestion via CI (matrix jobs per API)
4. Persisting UIDs to enable safe upserts and re-runs
5. Centralizing auth and environment templates
6. Scheduling periodic reconciliation to prevent drift

---

## Governance & Workspace Consolidation

This approach supports enterprise governance:

- Domain-based workspaces (Payments, Billing, etc.)
- PR-based ownership and review of API changes
- Role-based access controls in Postman
- Naming conventions and metadata tagging
- Archival policies for deprecated collections

---

## Repository Structure

- `specs/` — OpenAPI specifications
- `scripts/` — Ingestion and Postman API helpers
- `generated/` — Example collections, environments, logs
- `.env.example` — Configuration template
- `requirements.txt` — Dependencies

---

## Idempotency & Drift Detection

The ingestion script is safe to run on every merge:

- Computes a SHA256 hash of the OpenAPI spec
- Persists state (hash + UIDs) to `generated/state.json`
- Skips regeneration when no spec changes are detected
- Supports `--force` or `POSTMAN_FORCE=true` to override

