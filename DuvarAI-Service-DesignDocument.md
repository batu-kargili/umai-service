# DuvarAI Service Design Document

| **Author(s)** | Batu Kargili |
| --- | --- |
| **Version/Status** | v0.01 |
| **Date** | 27/12/25 |
| Content Description | This is a complete DuvarAI Service Design chapter: what it is, what it does, how it communicates (public API + internal Engine API), how configuration is stored (SQL Server) and distributed (Redis snapshots), and how it should be built and extended, aligned with the AI Engine contract and deployment model. |

## Table of Contents

### Introduction & Role in the Platform

**1.1 Purpose of DuvarAI Service**

**1.2 How DuvarAI Service Fits into DuvarAI Architecture**

**1.3 Responsibilities vs Non-Responsibilities**

**1.4 High-Level Request Flow (App → DuvarAI Service → AI Engine → LLM)**

### Architecture Overview

**2.1 Service Type & Deployment Model**

**2.2 Internal Layers & Modules**

**2.3 Trust Boundaries & Network Topology**

**2.4 State, Scaling & Horizontal Replicas**

### Core Data Structures & Contracts

**3.1 Public Request Contract (from Enterprise Apps)**

**3.2 Public Response Contract (to Enterprise Apps)**

**3.3 Internal Request Contract (to AI Engine)**

**3.4 Internal Response Handling (from AI Engine)**

**3.5 Error Object & Error Taxonomy**

**3.6 Guardrail Event & Audit Records**

### Configuration, Storage & Snapshot Distribution

**4.1 Source of Truth in SQL Server (Tenants/Envs/Projects/Guardrails/Policies)**

**4.2 Guardrail Versioning & Publish Flow**

**4.3 Redis Snapshot Schema & Key Patterns**

**4.4 Consistency Rules (Version Match, Rollback, Retention)**

### Authentication, RBAC & Licensing

**5.1 Auth Models (API Key, LDAP/JWT for Control Center)**

**5.2 RBAC Concepts (Tenant/Env/Project Scope)**

**5.3 License Enforcement (Hard Fail vs Soft Fail)**

**5.4 Secrets Handling (Keys, LDAP, LLM credentials)**

### API Surface

**6.1 App-Facing Guardrail APIs**

**6.2 Control-Center Admin APIs (Config & Testing)**

**6.3 Internal Ops APIs (Health/Readiness/Debug)**

### Observability & Operations

**7.1 Logging & Correlation (request_id end-to-end)**

**7.2 Metrics & SLOs (Latency, Block Rate, Engine Errors)**

**7.3 Alerts & Incident Signals (Engine Down, Redis Miss, License Expired)**

### Standalone Development of DuvarAI Service (MVP)

**8.1 Development Plan (MVP Service + SQL Server + Redis + Engine)**

**8.2 Deployment & Execution Plan (Local → Docker → K8s)**

**8.3 Implementation Notes & Reference Layout**

# Introduction & Role in the Platform

## 1.1 Purpose of DuvarAI Service

DuvarAI Service is the **control plane & public API** of the DuvarAI Platform. It sits between enterprise applications and the AI Engine to ensure every guardrail evaluation is:

- **Authenticated and authorized** (API key / JWT / LDAP-backed sessions)
- **License-valid** (1-year enterprise license enforcement)
- **Resolved to the correct configuration** (tenant → environment → project → guardrail → version)
- **Audited and observable** (events, metrics, alerts)
- **Routed internally** to AI Engine using a stable internal contract

In the overall platform model, DuvarAI Service is responsible for identity, licensing, and configuration resolution—then building the normalized internal request that AI Engine evaluates.

## 1.2 How DuvarAI Service Fits into DuvarAI Architecture

DuvarAI Service is one of the three core platform components:

- **Control Center (Next.js)** – Customer UI for managing environments/projects/guardrails/policies
- **DuvarAI Service (FastAPI)** – **Control plane + public APIs + config & licensing**
- **AI Engine (FastAPI)** – Policy execution & optional LLM interaction

The AI Engine is not directly reachable by enterprise apps; DuvarAI Service is the only caller of AI Engine and is responsible for the “front door” API and governance checks

## 1.3 Responsibilities vs Non-Responsibilities

DuvarAI Service is responsible for:

- Public API (enterprise integration endpoints)
- Tenant/environment/project resolution
- Authentication (API key today; LDAP/JWT for operators)
- License enforcement and feature gating
- Config storage (SQL Server as source of truth)
- Guardrail versioning and publishing snapshots to Redis
- Calling AI Engine and returning a shaped response
- Persisting events/metrics and evaluating alert rules

DuvarAI Service is not responsible for:

- Running policies, regex evaluation, or model calls (AI Engine does that)
- Direct UI rendering (Control Center does that)
- Storing guardrail runtime config inside AI Engine (engine reads snapshots from Redis)

## 1.4 High-Level Request Flow (App → DuvarAI Service → AI Engine → LLM)

1. **App → DuvarAI Service**
    
    Enterprise AI app calls a guard endpoint with an access key and chat payload.
    
2. **DuvarAI Service: Auth, License, Config**
    
    Service authenticates the key, checks RBAC/license validity, resolves tenant/env/project/guardrail and version, and prepares an internal evaluation request. 
    
3. **DuvarAI Service → AI Engine**
    
    Service calls AI Engine over internal network using the internal contract.
    
4. **AI Engine → (optional) LLM**
    
    AI Engine loads the guardrail snapshot from Redis, runs preflight + policies in parallel, short-circuits on first BLOCK, returns decision. 
    
5. **AI Engine → DuvarAI Service**
    
    Service records event/metrics, runs alert evaluation, returns a public response.
    

## 

# Architecture Overview

## 2.1 Service Type & Deployment Model

DuvarAI Service is a **stateless (at node-level) control-plane microservice** implemented in Python (FastAPI) and deployed as a containerized service inside the enterprise infrastructure.

At a high level:

- **Runtime:** Python 3.11+, FastAPI, Uvicorn/Gunicorn
- **Deployment:** Kubernetes (preferred) or Docker
- **Exposure:**
    - Exposed to enterprise apps via internal network / API gateway
    - Exposed to operators/admins via Control Center + Service
- **Scaling:** Horizontally scalable replicas (shared SQL Server and Redis; AI Engine separate)

Note: While the service nodes are stateless, the **system is stateful** via SQL Server (source of truth) and Redis (runtime snapshot cache).

---

## 2.2 Internal Layers & Modules

DuvarAI Service is structured as a layered service:

1. **API Layer (FastAPI routes)**
- App-facing endpoints (guardrail guard)
- Admin endpoints (manage tenants/envs/projects/guardrails/policies)
- Health/ready endpoints
1. **Auth & RBAC Layer**
- API key validation for apps
- Operator auth (LDAP → session/JWT for Control Center)
- RBAC decisions: tenant/env/project scope
1. **License & Entitlements Layer**
- License expiry hard fail
- Feature flags per license tier (future)
1. **Config Resolver Layer (SQL Server)**
- Resolve: api_key → tenant/env/project
- Resolve: guardrail_id → current_version
- Resolve: guardrail_version → guardrail snapshot materialization input
1. **Snapshot Publisher Layer (Redis)**
- Build guardrail snapshot JSON
- Write to Redis using versioned keys
- Optional: cache warm-up / publish hooks on deployment
1. **AI Engine Proxy Layer**
- Build InternalRequest
- Call AI Engine (httpx async)
- Map InternalResponse to public response
1. **Event & Telemetry Layer**
- Append-only evaluation events (SQL Server)
- Metrics counters / latencies
- Alert rule evaluation (MVP: minimal)

---

## 2.3 Trust Boundaries & Network Topology

Trust boundaries:

- **Enterprise Apps → DuvarAI Service:** untrusted edge (requires auth + rate limits + validation)
- **DuvarAI Service → AI Engine:** trusted internal channel (cluster-local; strict network policy)
- **DuvarAI Service → SQL Server:** control-plane storage (source of truth)
- **DuvarAI Service → Redis:** runtime snapshot publication / reads for quick routing
- **AI Engine → Redis:** reads snapshots only (engine never writes)
- **AI Engine → LLM endpoints:** only approved destinations (on-prem GPU / router)

Network policy intent:

- AI Engine accepts inbound **only** from DuvarAI Service.
- DuvarAI Service is the only writer of guardrail snapshots

## 2.4 State, Scaling & Horizontal Replicas

DuvarAI Service instances are stateless at the node level (no durable local state). System state lives in:

- **SQL Server** as the **control-plane source of truth**:
    - tenants (organizations)
    - environments
    - projects
    - guardrails + versions
    - policies
    - API keys, licenses, RBAC (later)
    - audit/event records
- **Redis** as the **runtime snapshot store**:
    - immutable guardrail snapshot JSON keyed by `{tenant, env, project, guardrail, version}`

Horizontal scaling:

- Scale DuvarAI Service replicas independently of AI Engine.
- Use a DB connection pool; enforce tenant scope with a per-request session context (see §4.1 + §8.1/§8.2).
- Redis writes are mostly on config publish, not on every request (reads happen at runtime by AI Engine).

On-prem constraint:

- SQL Server runs on enterprise-controlled infrastructure (VM/K8s/managed internal DB).
- Local development uses **SQL Server Docker**.

# Core Data Structures & Contracts

## 3.1 Public Request Contract (from Enterprise Apps)

The public request is what enterprise apps send to DuvarAI Service.

Goals:

- Compact and stable
- Supports full chat history
- Minimal metadata (optional)
- Explicit phase (PRE_LLM now; POST_LLM later)

Conceptual JSON:

```json
{
"conversation_id":"conv-123",
"phase":"PRE_LLM",
"guardrail_id":"gr-main-chat",
"input":{
"messages":[
{"role":"user","content":"suriye savaşı ne zaman biter"}
],
"phase_focus":"LAST_USER_MESSAGE",
"content_type":"text",
"language":"tr"
},
"timeout_ms":1500
}

```

Auth is provided via header (example):

- `Authorization: Bearer <access_key>` or `X-DuvarAI-Api-Key: <key>`

---

## 3.2 Public Response Contract (to Enterprise Apps)

The public response is what DuvarAI Service returns back to apps.

Design goals:

- Single clear decision (ALLOW/BLOCK/ALLOW_WITH_WARNINGS)
- Safe for app usage
- Does not expose internal policy lists; can include triggering_policy summary

Conceptual JSON:

```json
{
"request_id":"uuid-1234",
"decision":{
"action":"BLOCK",
"allowed":false,
"severity":"HIGH",
"reason":"Policy violation detected"
},
"category":"P1",
"triggering_policy":{
"policy_id":"pol-oss-main",
"type":"CONTEXT_AWARE",
"status":"BLOCK"
},
"latency_ms":210,
"errors":[]
}

```

Rule consistency: if decision is ALLOW, triggering_policy should be null/omitted (same philosophy as AI Engine’s internal contract). 
5a7cb65a-36d6-438c-b245-274b0fe…

---

## 3.3 Internal Request Contract (to AI Engine)

DuvarAI Service sends a normalized internal request to:

`POST /internal/ai-engine/v1/evaluate`

Key rule: **policy details are not in the request**; AI Engine loads the guardrail snapshot from Redis using IDs + version. 
5a7cb65a-36d6-438c-b245-274b0fe…

DuvarAI Service constructs:

- tenant_id / environment_id / project_id
- guardrail_id / guardrail_version
- phase
- input.messages + phase_focus

(Shape is aligned to the AI Engine design contract.) 
5a7cb65a-36d6-438c-b245-274b0fe…

---

## 3.4 Internal Response Handling (from AI Engine)

AI Engine returns:

- decision object
- triggering_policy (only the blocking policy for early-block behavior)
- latency info
- errors

DuvarAI Service must:

1. Correlate by request_id
2. Persist an event record (append-only)
3. Update metrics
4. Evaluate alert rules
5. Transform into public response format

This mirrors the behavior described in the AI Engine response section (single triggering policy, short-circuit on BLOCK). 
5a7cb65a-36d6-438c-b245-274b0fe…

---

## 3.5 Error Object & Error Taxonomy

DuvarAI Service errors must be explicit and stable:

**Auth & RBAC**

- `AUTH_MISSING`
- `AUTH_INVALID`
- `FORBIDDEN`

**License**

- `LICENSE_EXPIRED`
- `LICENSE_SUSPENDED`

**Config**

- `GUARDRAIL_NOT_FOUND`
- `ENV_NOT_FOUND`
- `PROJECT_NOT_FOUND`
- `CONFIG_STALE` (version mismatch)

**Dependencies**

- `AI_ENGINE_UNREACHABLE`
- `AI_ENGINE_TIMEOUT`
- `REDIS_UNAVAILABLE`
- `SQLSERVER_UNAVAILABLE`

Return shape (conceptual):

```json
{
"error":{
"type":"LICENSE_EXPIRED",
"message":"License expired for tenant ent-acme",
"retryable":false
}
}

```

---

## 3.6 Guardrail Event & Audit Records

DuvarAI Service writes append-only event records to SQL Server for:

- who called (api_key_id / subject)
- tenant/env/project/guardrail/version
- decision (action/allowed/severity/category)
- timestamps + latency
- triggering_policy summary
- error summaries

These records power:

- metrics dashboards
- alert rules
- compliance audits
- Control Center “History” pages (later)

---

# Configuration, Storage & Snapshot Distribution

## 4.1 Source of Truth in SQL Server (Tenant Virtualization)

**SQL Server is the source of truth** for all control-plane objects:

- Tenants / Organizations
- Environments
- Projects
- Guardrails + Guardrail Versions
- Policies + assignments
- API keys + licenses
- Audit/events

AI Engine never reads this DB directly; it depends on Redis snapshots.

### Tenant isolation model (recommended)

You have two on-prem friendly options:

**Option A — Row-Level Security (RLS) with SESSION_CONTEXT (recommended for MVP+)**

- Every tenant table has `tenant_id` (uniqueidentifier).
- DuvarAI Service sets tenant scope per request using SQL Server session context:
    - `EXEC sp_set_session_context @key=N'tenant_id', @value=@TenantId;`
- RLS enforces `tenant_id = SESSION_CONTEXT(N'tenant_id')`.

**Option B — Database-per-tenant (only if required by enterprise)**

- Strong isolation but operationally heavier:
    - migrations per tenant, connection management, reporting complexity.

**DuvarAI recommendation:** Start with **Option A (RLS)**. It gives strong isolation without exploding ops.

### Critical pooling rule (do not leak tenant context)

Because connections are pooled, DuvarAI Service must:

- Set tenant context at the start of every request transaction
- Clear tenant context at the end (or ensure reset before connection returns to pool)

---

## 4.2 Guardrail Versioning & Publish Flow (DB + Redis)

Publishing a guardrail version is a **two-phase control-plane action**:

1. **Persist** the new version in SQL Server:
- Validate schema and references (policies, LLM backends)
- Increment version (vN → vN+1)
- Store immutable `guardrail_versions.snapshot_json`
- Update `guardrails.current_version`
1. **Publish** the exact `snapshot_json` to Redis:
- `SET guardrail:{tenant}:{env}:{project}:{guardrail}:{version} <snapshot_json>`
- Optionally warm/verify by performing a test read.

AI Engine only ever reads snapshots; it does not read SQL Server directly.

---

## 4.3 Redis Snapshot Schema & Key Patterns (Unchanged)

Key pattern remains deterministic:

`guardrail:{tenant_id}:{environment_id}:{project_id}:{guardrail_id}:{guardrail_version}`

Value is the full GuardrailSnapshot JSON.

---

## 4.4 Consistency Rules (Version Match, Rollback, Retention)

- Strict version matching:
    - DuvarAI Service must send `guardrail_version` explicitly
    - AI Engine must fail if snapshot key is missing (no implicit fallback)
- Rollback:
    - Set `current_version` back to an earlier version in SQL Server and re-publish that snapshot to Redis
- Retention:
    - Keep all historical guardrail versions in SQL Server for audit
    - Redis can keep all versions (no TTL) or use a bounded retention policy, depending on enterprise requirements

# Authentication, RBAC & Licensing

## 5.1 Auth Models (API Key, LDAP/JWT for Control Center)

App auth (MVP):

- API key in header
- Maps to tenant/env/project scope

Operator auth (later):

- LDAP login (Control Center)
- Service issues JWT/session
- RBAC enforced on admin endpoints

---

## 5.2 RBAC Concepts (Tenant/Env/Project Scope)

RBAC scopes:

- Tenant admin: manage tenant-wide assets
- Env admin: manage env configs
- Project admin: manage project guardrails/policies
- Read-only auditor

---

## 5.3 License Enforcement (Hard Fail vs Soft Fail)

License expiry is a **hard fail**:

- If expired: return error and do not call AI Engine
- Also block access to Control Center admin actions

Future: some licenses may support “monitor-only” degraded mode, but default is strict.

---

## 5.4 Secrets Handling (Keys, LDAP, LLM credentials)

- API keys: store hashed in SQL Server
- LDAP bind secrets: K8s secrets / Docker secrets
- LLM keys (if any): store encrypted or external secret store; never plaintext in SQL Server backups
- Redis auth: secret-managed

# API Surface

## 6.1 App-Facing Guardrail APIs

MVP endpoints (suggested):

- `POST /api/v1/guardrails/{guardrail_id}/guard`
    - validates auth/license
    - resolves guardrail current_version
    - calls AI Engine
    - returns decision

---

## 6.2 Control-Center Admin APIs (Config & Testing)

MVP admin endpoints (even without UI yet):

- `POST /api/v1/admin/tenants`
- `POST /api/v1/admin/environments`
- `POST /api/v1/admin/projects`
- `POST /api/v1/admin/guardrails` (create + publish v1 snapshot)
- `POST /api/v1/admin/guardrails/{id}/publish` (publish new version)
- `POST /api/v1/admin/test/guard` (calls AI Engine with a chosen guardrail)

---

## 6.3 Internal Ops APIs (Health/Readiness/Debug)

- `GET /healthz` (service process ok)
- `GET /readyz` (db reachable, redis reachable, engine reachable)

---

# Observability & Operations

## 7.1 Logging & Correlation (request_id end-to-end)

- Generate request_id if missing
- Propagate request_id to AI Engine internal request
- Structured logs include tenant/env/project/guardrail/version/decision

---

## 7.2 Metrics & SLOs

Key metrics:

- request latency (p50/p95/p99)
- block rate
- engine error rate
- redis miss rate for snapshots
- license failure count

---

## 7.3 Alerts & Incident Signals

Alert conditions:

- AI Engine unreachable
- Redis unavailable or snapshot miss spikes
- License expiration approaching / expired
- Unusual spike in BLOCK for a project

# 8. Standalone Development (MVP) – Updated for SQL Server Docker

## 8.1 Development Plan (MVP Service + SQL Server + Redis + Engine)

MVP objective:

- DuvarAI Service stores org/env/project/guardrail/policy in **SQL Server**
- DuvarAI Service publishes guardrail snapshots to **Redis**
- DuvarAI Service calls **AI Engine** and returns public decision response
- DuvarAI Service records minimal **audit events** in SQL Server (recommended)

Implementation steps:

1. Create FastAPI service skeleton (public guard endpoint + admin endpoints)
2. Bring up SQL Server locally via Docker (see §8.2)
3. Implement DB schema migrations (Alembic) for:
    - tenants, envs, projects, guardrails, versions, policies, key mappings
4. Implement “tenant context” middleware / DB helper:
    - `EXEC sp_set_session_context @key=N'tenant_id', @value='<uuid>'` per request
    - clear with `EXEC sp_set_session_context @key=N'tenant_id', @value=NULL`
5. Implement snapshot builder + Redis publisher
6. Implement guard endpoint:
    - auth → licence → resolve guardrail/version → call AI Engine → map response
7. Add tests: tenant scoping, publish flow, engine proxy behavior

---

## 8.2 Local Deployment & Execution Plan (Docker-first, On-Prem Compatible)

### Local SQL Server Docker (required)

Run SQL Server locally using the official image:

```bash
docker run -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=YourStrong!Passw0rd" -p 1433:1433 --name duvarai-sqlserver -d mcr.microsoft.com/mssql/server:2022-latest
```

Connect via:

```bash
sqlcmd -S localhost,1433 -U sa -P "YourStrong!Passw0rd"
```

Notes:

- Password must meet SQL Server complexity rules.
- If port 1433 conflicts, change the host port (e.g., `-p 1434:1433`).
- For persistent data, add a Docker volume mount.

### Local Stack (recommended docker-compose)

Local dev should run:

- `sqlserver`
- `redis`
- `ai-engine`
- `duvarai-service`

DuvarAI Service env vars (example):

- `DUVARAI_DATABASE_URL=mssql+aioodbc://sa:YourStrong!Passw0rd@host.docker.internal:1433/duvarai?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes`
- `DUVARAI_REDIS_URL=redis://redis:6379`
- `DUVARAI_AI_ENGINE_BASE_URL=http://ai-engine:8081`

---

# 9. Implementation Documentation

Below is a **repo-ready, standalone “Implementation Documentation”** for **DuvarAI Service (MVP)** that matches what we’ve designed:

- **Source of truth:** **SQL Server (tenant isolation via RLS or tenant_id filters)** running via **Docker locally**
- **Runtime config for AI Engine:** **Redis Guardrail Snapshots**
- **Execution:** DuvarAI Service calls **AI Engine** (internal HTTP) using the internal request you already have
- **On-prem compatible:** everything is containerized, no cloud dependencies required

---

### DuvarAI Service (MVP) — Implementation Documentation

## 9.0. MVP Scope

### What we build now

DuvarAI Service MVP provides:

1. **Public Guard API** (enterprise app calls Service)
2. **Auth (API key)** + **License check**
3. **Config resolution** (tenant/env/project/guardrail/version) from **SQL Server**
4. **Publish guardrail snapshots to Redis** (admin publish flow)
5. **Proxy evaluation to AI Engine** and return a **public response**
6. **Audit event recording** (minimal) in SQL Server

### What we skip for now

- Control Center UI integration (Next.js)
- LDAP login + RBAC UI flows (we design interfaces but defer)
- Kafka + advanced metrics pipeline

---

## 9.1. System Components

- **DuvarAI Service** (FastAPI): control plane + public API
- **SQL Server**: source of truth + tenant isolation
- **Redis**: guardrail snapshots (runtime config for AI Engine)
- **AI Engine**: executes guardrails/policies (already implemented)

---

## 9.2. Repo Layout

Recommended structure:

```
duvarai-service/
  app/
    main.py
    api/
      public.py
      admin.py
      ops.py
    core/
      settings.py
      auth.py
      license.py
      resolver.py
      snapshots.py
      engine_client.py
      db.py
      events.py
    models/
      public_api.py
      engine_proxy.py
      domain.py
  migrations/                 # Alembic
  tests/
    test_auth.py
    test_publish.py
    test_guard.py
  docker-compose.yml
  Dockerfile
  pyproject.toml
  README.md

```

---

## 9.3. Local Development Stack (On-Prem, Docker-first)

### 9.3.1 Start **SQL Server** locally (required)

**SQL Server Docker:**

```bash
docker run -e "ACCEPT_EULA=Y" \
  -e "MSSQL_SA_PASSWORD=YourStrong!Passw0rd" \
  -p 1433:1433 \
  --name duvarai-sqlserver \
  -d mcr.microsoft.com/mssql/server:2022-latest

```

Create a database (example using `sqlcmd` from another container or your host):

```bash
docker exec -it duvarai-sqlserver /opt/mssql-tools/bin/sqlcmd \
  -S localhost -U sa -P"YourStrong!Passw0rd" \
  -Q"CREATE DATABASE DuvarAI;"

```

### 9.3.2 Local Redis + AI Engine + Service via docker-compose

Create `docker-compose.yml`:

```yaml
services:
redis:
image:redis:7-alpine
ports: ["6379:6379"]

ai-engine:
image:duvarai/ai-engine:local
ports: ["8081:8081"]
environment:
REDIS_URL:redis://redis:6379
depends_on: [redis]

duvarai-service:
build:.
ports: ["8080:8080"]
environment:
DUVARAI_DATABASE_URL:mssql+aioodbc://sa:YourStrong!Passw0rd@host.docker.internal:1433/DuvarAI?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes
DUVARAI_REDIS_URL:redis://redis:6379
DUVARAI_AI_ENGINE_BASE_URL:http://ai-engine:8081
# optional:
# LOG_LEVEL: INFO
depends_on: [redis,ai-engine]

```

Notes:

- `host.docker.internal` works on Docker Desktop. On Linux, use `-network host` or point to the container IP / run SQL Server also inside compose.
- Replace DB URL credentials based on your SQL Server container settings.

---

## 9.4. Data Model in SQL Server (Source of Truth)

### 9.4.1 Tenant Isolation Rule

Every tenant-scoped table must include:

- `tenant_id uniqueidentifier NOT NULL`

And **every DB request must set tenant context** on the connection/transaction.

### 9.4.2 Minimal Tables (MVP)

You can implement these in Alembic migrations:

1. `tenants`
- `tenant_id` (uniqueidentifier pk)
- `name`
- `status` (active/suspended)
- `created_at`
1. `api_keys`
- `id` (uniqueidentifier pk)
- `tenant_id` (fk)
- `key_hash` (string)
- `environment_id` (string)
- `project_id` (string nullable)
- `created_at`
- `revoked` (bool)
1. `licenses`
- `tenant_id` (uniqueidentifier pk/fk)
- `expires_at` (timestamp)
- `status` (active/suspended)
- `features_json` (nvarchar(max) JSON optional)
1. `environments`
- `(tenant_id, environment_id)` unique
- `environment_id` (string)
- `name`
1. `projects`
- `(tenant_id, environment_id, project_id)` unique
- `project_id` (string)
- `name`
1. `guardrails`
- `(tenant_id, environment_id, project_id, guardrail_id)` unique
- `guardrail_id` (string)
- `name`
- `current_version` (int)
- `mode` (ENFORCE/MONITOR)
1. `guardrail_versions`
- same keys + `version` (int)
- `snapshot_json` (nvarchar(max) JSON)
- `created_at`
1. `audit_events` (minimal but recommended)
- `id` (uniqueidentifier)
- `tenant_id`, `environment_id`, `project_id`
- `guardrail_id`, `guardrail_version`
- `request_id`, `phase`, `action`, `allowed`, `category`
- `created_at`

---

## 9.5. DB Access Pattern (SQL Server Tenant Context + Connection Pools)

This is **the most important implementation rule**.

### 9.5.1 Rule: Tenant context must never leak between requests

With pooled connections, you must ensure tenant context is set **per transaction** and **reset** reliably.

### 9.5.2 Recommended approach (request-scoped session context)

Use SQL Server session context with RLS and clear it before returning the connection to the pool:

- Start transaction
- `EXEC sp_set_session_context @key=N'tenant_id', @value=:tenant_id`
- Run queries (RLS enforces tenant_id)
- Clear session context after request: `EXEC sp_set_session_context @key=N'tenant_id', @value=NULL`

Example snippet (pseudo):

```python
async with session.begin():
    await session.execute(
        text("EXEC sp_set_session_context @key=N'tenant_id', @value=:tid"),
        {"tid": tenant_id},
    )
    # tenant-scoped queries here

await session.execute(
    text("EXEC sp_set_session_context @key=N'tenant_id', @value=NULL")
)
```

---

## 9.6. Redis Snapshot Storage (Runtime Config)

### 9.6.1 Key format (immutable, versioned)

Use deterministic keys:

```
guardrail:{tenant_id}:{environment_id}:{project_id}:{guardrail_id}:{version}

```

### 9.6.2 Value

Store the **full GuardrailSnapshot JSON** (exact shape AI Engine expects).

### 9.6.3 Publish rules

- Service publishes on:
    - guardrail create
    - guardrail version publish
    - rollback publish
- Engine reads only; Service is only writer.

---

## 9.7. Service APIs (MVP)

### 9.7.1 Public API — Guard

**POST** `/api/v1/guardrails/{guardrail_id}/guard`

Headers:

- `X-DuvarAI-Api-Key: <key>`
- `Content-Type: application/json`

Body (public minimal):

```json
{
"conversation_id":"conv-123",
"phase":"PRE_LLM",
"input":{
"messages":[{"role":"user","content":"..."}],
"phase_focus":"LAST_USER_MESSAGE",
"content_type":"text",
"language":"tr"
},
"timeout_ms":2000
}

```

Service steps (exact):

1. Validate API key → resolve `tenant_id`, `environment_id`, optional `project_id`
2. License check for tenant
3. Resolve `project_id` (if not fixed by key) and resolve:
    - `guardrail_version = guardrails.current_version`
4. Build internal request to AI Engine
5. Call AI Engine, get internal response
6. Persist audit event
7. Return public response

### 9.7.2 Admin API — Bootstrap + Publish

You need admin endpoints to create config without Control Center UI.

Minimum set:

1. **POST** `/api/v1/admin/tenants`
2. **POST** `/api/v1/admin/tenants/{tenant_id}/license`
3. **POST** `/api/v1/admin/api-keys`
4. **POST** `/api/v1/admin/environments`
5. **POST** `/api/v1/admin/projects`
6. **POST** `/api/v1/admin/guardrails`
7. **POST** `/api/v1/admin/guardrails/{guardrail_id}/versions` (create new version)
8. **POST** `/api/v1/admin/guardrails/{guardrail_id}/publish/{version}` (writes Redis snapshot)

MVP simplification:

- `/guardrails/{id}/versions` accepts the full `snapshot_json` you already use in AI Engine (or the higher-level config and Service builds snapshot).
- `/publish` writes snapshot_json to Redis.

### 9.7.3 Ops API

- **GET** `/healthz` (process ok)
- **GET** `/readyz` (db ok + redis ok + ai-engine ok)

---

## 9.8. AI Engine Integration (Internal Client)

### 9.8.1 Internal endpoint used

Service calls:

`POST {AI_ENGINE_BASE_URL}/internal/ai-engine/v1/evaluate`

### 9.8.2 Internal request shape (match what you already send)

Service must generate:

- `request_id` (uuid)
- `tenant_id`, `environment_id`, `project_id`
- `guardrail_id`, `guardrail_version`
- `phase` (PRE_LLM now)
- `input.messages` (full history)
- `timeout_ms`
- `flags.allow_llm_calls = true/false` (configurable per tenant/license)

### 9.8.3 Internal response handling

- If Engine returns BLOCK:
    - Service returns BLOCK immediately (no extra aggregation)
- If Engine returns ALLOW:
    - Service returns ALLOW
- If Engine times out/unreachable:
    - Service returns `AI_ENGINE_UNREACHABLE` or `AI_ENGINE_TIMEOUT`
    - recommended default posture: **fail-closed** (BLOCK) only if enterprise policy demands it; otherwise return explicit error.

---

## 9.9. Authentication & Licensing (MVP)

### 9.9.1 API Key auth

- Store only `key_hash` in DB (never plaintext)
- On request:
    - hash incoming key
    - lookup active key
    - get tenant/env/project scope

### 9.9.2 License enforcement

- On each request:
    - load `licenses` for tenant
    - if expired or suspended:
        - reject without calling AI Engine
- Response:
    - `403` (or `402` if you prefer “payment required”-style semantics internally)
    - stable error type: `LICENSE_EXPIRED`

---

## 9.10. End-to-End Local Runbook (MVP)

### Step A — Start dependencies

1. Start SQL Server container
2. `docker compose up redis ai-engine`

### Step B — Start duvarai-service

`docker compose up duvarai-service`

### Step C — Bootstrap config via admin endpoints

1. Create tenant
2. Create license (expires in 1 year)
3. Create environment, project
4. Create guardrail v1 (store snapshot_json in DB)
5. Publish v1 to Redis

### Step D — Call public guard

Enterprise app calls:

`POST /api/v1/guardrails/gr-main/guard`

Service resolves + calls engine + returns result.

---

## 9.11. Testing Plan (MVP)

### Unit tests

- Auth: missing key, invalid key, revoked key
- License: expired, suspended, valid
- Resolver: guardrail not found, env/project mismatch
- Snapshot publishing: key format correctness, Redis write

### Integration tests

- Spin up test containers (SQL Server + Redis) and a mocked AI Engine
- Verify:
    - publish writes Redis
    - guard calls AI Engine with correct internal request
    - returns correct public response

---

## 9.12. Production Notes (On-Prem)

### 9.12.1 Database

- MVP uses SQL Server docker locally; in production on-prem:
    - Run SQL Server in Kubernetes (StatefulSet) or VM-based SQL Server deployment
    - Backups + HA plan (Patroni, etc.) depending on the enterprise

### 9.12.2 Redis

- Run Redis as a HA setup (Sentinel/Cluster) if required

### 9.12.3 Networking

- AI Engine must be internal-only
- Service is the only allowed caller to AI Engine
- Redis should be internal-only

### 9.12.4 Security

- Always hash API keys
- Do not log raw user messages in production logs
- Rate limit at gateway/service
- Keep strict dependency pinning

---

## 9.13. MVP Deliverables Checklist

- [ ]  FastAPI app + routes (public/admin/ops)
- [ ]  SQL Server schema + Alembic migrations
- [ ]  Tenant-context DB helper (sp_set_session_context)
- [ ]  Redis publisher for snapshots
- [ ]  Engine client (httpx async)
- [ ]  Evaluate endpoint end-to-end
- [ ]  Minimal audit events
- [ ]  docker-compose local stack
- [ ]  tests (unit + integration)
