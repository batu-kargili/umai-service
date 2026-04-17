# umai-service ↔ umai-control-center API Contract

This document describes exactly what `umai-control-center` expects from `umai-service`.
Hand this to the backend team so there are no integration surprises.

---

## Network topology

```
Browser  →  control-center (:3000)  →  umai-service (:8080)
```

The control center acts as a **server-side proxy**. The browser never calls the service directly.
All requests to the service originate from within the Docker network (`umai-public`).

The two base URLs the control center connects to:

| Env var                        | Default (docker-compose)                   | Used for                        |
|--------------------------------|--------------------------------------------|---------------------------------|
| `CONTROL_CENTER_ADMIN_API_URL` | `http://umai-service:8080/api/v1/admin`    | All management operations       |
| `CONTROL_CENTER_PUBLIC_API_URL`| `http://umai-service:8080/api/v1`          | Unauthenticated public endpoints|

---

## Request headers forwarded to the service

The proxy only forwards these three headers. The service must rely on them:

| Header         | When present                                      |
|----------------|---------------------------------------------------|
| `Content-Type` | All requests with a body                          |
| `Accept`       | When set by the client                            |
| `X-Tenant-Id`  | All tenant-scoped requests (see endpoint table)   |

No `Authorization` header is forwarded. Authentication between the control center and
the service is network-trust only (they share the `umai-public` Docker network).

---

## Error response format

The control center parses errors from any of these three shapes. Return one consistently:

```json
{ "error": { "message": "Human-readable description" } }
{ "detail": { "message": "Human-readable description" } }
{ "message": "Human-readable description" }
```

---

## Admin API endpoints — `/api/v1/admin`

### Tenants & License

| Method | Path                            | Headers          | Notes                              |
|--------|---------------------------------|------------------|------------------------------------|
| GET    | `/tenants`                      |                  | Returns `Tenant[]`                 |
| GET    | `/tenants/{tenant_id}/license`  |                  | Returns `License` or **404**       |
| POST   | `/licenses/apply`               | `Content-Type`   | Body: `{ token: string }`          |

**Tenant object:**
```json
{ "tenant_id": "uuid", "name": "string", "status": "string", "created_at": "ISO8601?" }
```

**License object:**
```json
{ "tenant_id": "uuid", "status": "string", "expires_at": "ISO8601", "features_json": {} }
```

---

### Environments

| Method | Path             | Headers          | Notes                    |
|--------|------------------|------------------|--------------------------|
| GET    | `/environments`  | `X-Tenant-Id`    | Returns `Environment[]`  |
| POST   | `/environments`  | `Content-Type`   | Body: see below          |

**Environment object:**
```json
{ "tenant_id": "uuid", "environment_id": "string", "name": "string" }
```

---

### Projects

| Method | Path                          | Headers        | Notes                  |
|--------|-------------------------------|----------------|------------------------|
| GET    | `/projects/{tenant_id}/{env_id}` |             | Returns `Project[]`    |
| POST   | `/projects`                   | `Content-Type` | Body: see below        |

**Project object:**
```json
{ "tenant_id": "uuid", "environment_id": "string", "project_id": "string", "name": "string" }
```

---

### API Keys

| Method | Path                   | Headers                    | Notes                                                  |
|--------|------------------------|----------------------------|--------------------------------------------------------|
| GET    | `/api-keys`            | `X-Tenant-Id`              | Query: `?environment_id=&project_id=`                  |
| POST   | `/api-keys`            | `Content-Type`             | Body: `{ tenant_id, environment_id, project_id, name? }`|
| DELETE | `/api-keys/{key_id}`   | `X-Tenant-Id`              | Returns the revoked key object                         |

**ApiKey object:**
```json
{
  "id": "uuid",
  "tenant_id": "uuid",
  "environment_id": "string",
  "project_id": "string | null",
  "api_key": "string | null",
  "name": "string | null",
  "key_preview": "string | null",
  "created_at": "ISO8601 | null",
  "revoked": false
}
```

---

### Policies

| Method | Path                                        | Headers                           | Notes                   |
|--------|---------------------------------------------|-----------------------------------|-------------------------|
| GET    | `/policies/{env_id}/{project_id}`           | `X-Tenant-Id`                     | Returns `Policy[]`      |
| POST   | `/policies`                                 | `Content-Type`                    |                         |
| PATCH  | `/policies/{env_id}/{project_id}/{policy_id}` | `Content-Type`, `X-Tenant-Id`   | Partial update          |

**Policy object:**
```json
{
  "tenant_id": "uuid",
  "environment_id": "string",
  "project_id": "string",
  "policy_id": "string",
  "name": "string",
  "type": "HEURISTIC | CONTEXT_AWARE",
  "enabled": true,
  "phases": ["PRE_LLM", "POST_LLM"],
  "config": {},
  "scope": "ORGANIZATION | ENVIRONMENT | PROJECT",
  "created_at": "ISO8601?"
}
```

---

### Guardrails

| Method | Path                                                          | Headers       | Notes                             |
|--------|---------------------------------------------------------------|---------------|-----------------------------------|
| GET    | `/guardrails/{env_id}/{project_id}`                           | `X-Tenant-Id` | Returns `Guardrail[]`             |
| POST   | `/guardrails`                                                 | `Content-Type`|                                   |
| GET    | `/guardrails/{env_id}/{project_id}/{guardrail_id}/versions`   | `X-Tenant-Id` | Returns `GuardrailVersion[]`      |
| POST   | `/guardrails/{guardrail_id}/versions`                         | `Content-Type`|                                   |
| POST   | `/guardrails/{guardrail_id}/publish/{version}`                | `Content-Type`| Returns `{ redis_key: string }`   |
| GET    | `/guardrails/{env_id}/{project_id}/{guardrail_id}/snapshot/{version}` | `X-Tenant-Id` | Returns `GuardrailSnapshotResponse` |
| POST   | `/guardrails/agentic`                                         | `Content-Type`, `X-Tenant-Id` | AI-generated guardrail draft |

**Guardrail object:**
```json
{
  "tenant_id": "uuid",
  "environment_id": "string",
  "project_id": "string",
  "guardrail_id": "string",
  "name": "string",
  "mode": "ENFORCE | MONITOR",
  "current_version": 1
}
```

**GuardrailVersion object:**
```json
{
  "tenant_id": "uuid",
  "environment_id": "string",
  "project_id": "string",
  "guardrail_id": "string",
  "version": 1,
  "created_at": "ISO8601?"
}
```

**GuardrailSnapshotResponse:**
```json
{
  "tenant_id": "uuid",
  "environment_id": "string",
  "project_id": "string",
  "guardrail_id": "string",
  "version": 1,
  "redis_key": "string",
  "redis_available": true,
  "redis_present": true,
  "snapshot": {
    "guardrail_id": "string",
    "version": 1,
    "mode": "ENFORCE | MONITOR",
    "phases": ["PRE_LLM"],
    "preflight": {},
    "policies": [],
    "llm_config": {}
  }
}
```

---

### Guardrail Testing

| Method | Path         | Headers        | Notes                         |
|--------|--------------|----------------|-------------------------------|
| POST   | `/test/guard` | `Content-Type` | Run a guardrail against input |

**Request body:**
```json
{
  "tenant_id": "uuid",
  "environment_id": "string",
  "project_id": "string",
  "guardrail_id": "string",
  "guardrail_version": 1,
  "phase": "PRE_LLM | POST_LLM",
  "input": {
    "messages": [{ "role": "user | assistant | system", "content": "string" }],
    "phase_focus": "LAST_USER_MESSAGE | LAST_ASSISTANT_MESSAGE",
    "content_type": "text | markdown | json",
    "language": "string?"
  },
  "timeout_ms": 5000,
  "allow_llm_calls": true
}
```

**Response:**
```json
{
  "request_id": "uuid",
  "guardrail_id": "string",
  "guardrail_version": 1,
  "phase": "PRE_LLM",
  "decision": {
    "action": "ALLOW | BLOCK | FLAG",
    "allowed": true,
    "severity": "NONE | LOW | MEDIUM | HIGH | CRITICAL",
    "reason": "string"
  },
  "triggering_policy": null,
  "latency_ms": { "total": 42, "preflight": null },
  "errors": []
}
```

---

### Alerts

| Method | Path                               | Headers       | Notes                                |
|--------|------------------------------------|---------------|--------------------------------------|
| GET    | `/alerts/{env_id}/{project_id}`    | `X-Tenant-Id` | Query: `?limit=50`                   |

**AlertItem object:**
```json
{
  "id": "uuid",
  "workflow": "string",
  "flow": "string",
  "category": "string",
  "policy": "string",
  "guardrail_id": "string",
  "decision": "BLOCK | FLAG",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "phase": "PRE_LLM | POST_LLM",
  "latency_ms": 42,
  "created_at": "ISO8601",
  "message": "string",
  "request_id": "uuid",
  "matched_rule": "string"
}
```

---

### Audit Events

| Method | Path                    | Headers       | Notes                                                                           |
|--------|-------------------------|---------------|---------------------------------------------------------------------------------|
| GET    | `/audit-events`         | `X-Tenant-Id` | Query: `?environment_id=&project_id=&guardrail_id=&action=&phase=&limit=` (max 500) |
| GET    | `/audit-events/export`  | `X-Tenant-Id` | Same query params; returns plain text (CSV/similar). Max 1000 rows.             |

---

### Evaluation

| Method | Path                        | Headers       | Notes                                               |
|--------|-----------------------------|---------------|-----------------------------------------------------|
| GET    | `/evaluations/sets`         |               | Returns `EvaluationSet[]`                           |
| GET    | `/evaluations`              | `X-Tenant-Id` | Query: `?environment_id=&project_id=`               |
| GET    | `/evaluations/{run_id}`     | `X-Tenant-Id` | Query: `?limit=50`; returns run + cases             |
| POST   | `/evaluations`              | `X-Tenant-Id` | Body: **multipart/form-data** (not JSON)            |

---

### Evidence Packs

| Method | Path                          | Headers        | Notes                                                          |
|--------|-------------------------------|----------------|----------------------------------------------------------------|
| GET    | `/evidence-packs`             | `X-Tenant-Id`  | Query: `?environment_id=&project_id=&regime=&limit=`           |
| POST   | `/evidence-packs`             | `Content-Type` | `regime`: `EU_AI_ACT \| GDPR \| CPRA_ADMT \| SEC_CYBER \| CUSTOM` |

---

### Policy & Guardrail Library

| Method | Path                          | Headers        | Notes                         |
|--------|-------------------------------|----------------|-------------------------------|
| GET    | `/library/policies`           |                | Returns `PolicyLibraryItem[]` |
| POST   | `/library/policies/deploy`    | `Content-Type` |                               |
| GET    | `/library/guardrails`         |                | Returns `GuardrailLibraryItem[]` |
| POST   | `/library/guardrails/deploy`  | `Content-Type` | Returns `GuardrailLibraryDeployResponse` |

---

### Browser Extension

| Method | Path                    | Headers       | Notes                                              |
|--------|-------------------------|---------------|----------------------------------------------------|
| GET    | `/extension/events`     | `X-Tenant-Id` | Query: `?site=&event_type=&decision=&device_id=&chain_valid=&from_ts=&to_ts=&limit=` |
| GET    | `/extension/summary`    | `X-Tenant-Id` | Query: `?days=7`. Returns `ExtensionSummary`       |

**ExtensionSummary object:**
```json
{
  "total_events": 0,
  "unique_devices": 0,
  "unique_users": 0,
  "blocked_events": 0,
  "warned_events": 0,
  "redacted_events": 0,
  "last_event_at": "ISO8601 | null",
  "by_site": {},
  "by_event_type": {},
  "by_decision": {},
  "daily": [{ "day": "YYYY-MM-DD", "count": 0 }]
}
```

---

## Public API endpoints — `/api/v1`

These are called **without** a session. No `X-Tenant-Id` header.

| Method | Path                    | Notes                                          |
|--------|-------------------------|------------------------------------------------|
| POST   | `/subscriptions/free`   | Body: `{ tenant_name: string, admin_email? }`. Returns `{ tenant_id, plan, license_expires_at }` |

---

## Browser Extension device token (JWT)

The control center issues short-lived JWTs for browser extension devices.
The service must validate these tokens on the extension ingest endpoint.

| Field    | Value                                    |
|----------|------------------------------------------|
| Algorithm | `HS256`                                 |
| Secret   | `EXTENSION_CONNECT_JWT_SECRET` env var  |
| Audience (`aud`) | `umai-ext-ingest`              |
| TTL      | 3600 seconds (1 hour)                   |
| `roles`  | `["tenant-device"]`                     |

**JWT claims:**
```json
{
  "sub": "<user LDAP subject>",
  "tenant_id": "<uuid>",
  "aud": "umai-ext-ingest",
  "iat": 1700000000,
  "exp": 1700003600,
  "roles": ["tenant-device"]
}
```

The service must reject tokens with a wrong `aud`, expired `exp`, or invalid signature.

---

## Response headers the proxy forwards back to the browser

| Header               |
|----------------------|
| `Content-Type`       |
| `Content-Disposition`|
| `Cache-Control`      |
| `Location`           |

All other response headers from the service are dropped by the proxy.
