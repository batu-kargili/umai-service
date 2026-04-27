# UMAI Platform Production Deployment

## Architecture

```
                        +----------------------+
                        |  umai-control-center |  :3000 (host-exposed)
                        |  Operator web UI     |
                        +----------+-----------+
                                   |
                                   | HTTP (internal)
                        +----------v-----------+
                        |     umai-service     |  :8080 (internal only)
                        |   REST API + admin   |
                        +----------+-----------+
                                   |
             +---------------------+---------------------+
             |                                           |
             | HTTP (internal)                           | Redis (internal)
   +---------v----------+                      +---------v---------+
   |    umai-engine     |  :9000              |       redis       |  :6379
   |   AI evaluation    |                     | snapshot storage  |
   +--------------------+                     +-------------------+
```

Each component is published as a separate repository on Docker Hub under the `umai` organization:

| Component | Image |
|-----------|-------|
| Control Center | `umai/umai-enterprise-control-center` |
| Service | `umai/umai-enterprise-service` |
| Engine | `umai/umai-enterprise-engine` |

Customers do not build anything. They configure and run the published images.

## Prerequisites

- Docker Engine 24+ and Docker Compose v2
- A PostgreSQL 15+ database reachable by `umai-service`
- An LDAP / Active Directory server for operator authentication
- A valid UMAI license bundle containing both the license token and the Ed25519 public key

## Quick Start

```bash
# 1. Download the deployment bundle
curl -L https://releases.umai.ai/latest/deploy.tar.gz | tar xz
cd umai-deploy

# 2. Create your configuration file
cp .env.example .env

# 3. Fill in all REQUIRED values in .env
#    At minimum:
#    UMAI_LICENSE_KEY
#    UMAI_LICENSE_PUBLIC_KEY
#    UMAI_ORGANIZATION_ID
#    UMAI_LICENSE_EXPIRES_AT
#    UMAI_SERVICE_SECRET_KEY
#    UMAI_DATABASE_URL
#    UMAI_SNAPSHOT_SIGNING_KEY
#    CC_SESSION_SECRET
#    CC_EXTENSION_JWT_SECRET
#    LDAP_URL
#    LDAP_BIND_DN
#    LDAP_BIND_PASSWORD
#    LDAP_USER_SEARCH_BASE

# 4. Generate secrets
openssl rand -hex 32   # UMAI_SERVICE_SECRET_KEY
openssl rand -hex 32   # UMAI_SNAPSHOT_SIGNING_KEY
openssl rand -hex 32   # CC_SESSION_SECRET
openssl rand -hex 32   # CC_EXTENSION_JWT_SECRET

# 5. Start the stack
docker compose up -d

# 6. Open the control center
open http://localhost:3000
```

On first startup, `umai-service` runs `alembic upgrade head` automatically before it begins serving traffic.

To bootstrap a PoC with a tenant, environment, project, and a published built-in guardrail, set `UMAI_RUN_SEED=true` and the `UMAI_SEED_*` variables before startup. The seed job is idempotent and can run on every restart.

## Configuration Reference

### License

| Variable | Required | Description |
|----------|----------|-------------|
| `UMAI_LICENSE_KEY` | Yes | License token from your purchase confirmation |
| `UMAI_LICENSE_PUBLIC_KEY` | Yes | Ed25519 public key from your UMAI license bundle |
| `UMAI_LICENSE_STRICT` | No | Fail startup when license verification fails. Default: `true` |
| `UMAI_ORGANIZATION_ID` | Yes | Organization UUID from your welcome email |
| `UMAI_ORGANIZATION_NAME` | No | Display name shown in the UI |
| `UMAI_ORGANIZATION_PLAN` | No | Plan tier. Default: `enterprise` |
| `UMAI_LICENSE_EXPIRES_AT` | Yes | Expiry from your license document (ISO 8601) |

### UMAI Service

| Variable | Required | Description |
|----------|----------|-------------|
| `UMAI_SERVICE_SECRET_KEY` | Yes | Random 32-byte hex secret for internal token signing |
| `UMAI_DATABASE_URL` | Yes | PostgreSQL connection string |
| `UMAI_CORS_ORIGINS` | No | Comma-separated allowed origins. Default: `http://localhost:3000` |
| `UMAI_REDIS_URL` | No | Redis URL for published guardrail snapshots. Default: bundled `redis://redis:6379/0` |
| `UMAI_SNAPSHOT_SIGNING_KEY` | Yes | Shared HMAC key for signing published guardrail snapshots |
| `UMAI_SNAPSHOT_SIGNING_KEY_ID` | No | Identifier stored with signed snapshots. Default: `default` |
| `UMAI_ENVIRONMENT` | Yes | Set to `production` for production runtime checks |
| `UMAI_ADMIN_AUTH_MODE` | Yes | Use `network-trust` only when service is internal-only; use `jwt` when directly exposed |
| `UMAI_DEFAULT_GUARDRAIL_LLM_BASE_URL` | Yes | OpenAI-compatible endpoint used by context-aware policies |
| `UMAI_DEFAULT_GUARDRAIL_LLM_MODEL` | Yes | Model used by context-aware policies |
| `UMAI_DEFAULT_GUARDRAIL_LLM_AUTH_SECRET_ENV` | Yes | Name of the engine env var containing the inference API key |

### Optional PoC Guardrail Bootstrap

Set these values to create and publish the Turkish regulated telecom guardrail during startup:

```bash
UMAI_RUN_SEED=true
UMAI_SEED_TENANT_ID=<same UUID as UMAI_ORGANIZATION_ID>
UMAI_SEED_TENANT_NAME=<customer display name>
UMAI_SEED_ENVIRONMENT_ID=prod
UMAI_SEED_ENVIRONMENT_NAME=Production
UMAI_SEED_PROJECT_ID=poc
UMAI_SEED_PROJECT_NAME=PoC
UMAI_SEED_GUARDRAIL_TEMPLATE_ID=gr-tr-regulated-telecom-sovereign-shield
UMAI_SEED_GUARDRAIL_ID=gr-tr-regulated-telecom-sovereign-shield
UMAI_SEED_GUARDRAIL_NAME=Turkiye Regulated Telecom Sovereign Shield
UMAI_SEED_PUBLISH_GUARDRAIL=true
```

### Control Center - Session

| Variable | Required | Description |
|----------|----------|-------------|
| `CC_SESSION_SECRET` | Yes | Random 32-byte hex secret for session JWT signing |
| `CC_SESSION_TTL_SECONDS` | No | Session lifetime in seconds. Default: `43200` |
| `CC_HOST_PORT` | No | Host port for the UI. Default: `3000` |
| `CC_EXTENSION_JWT_SECRET` | Yes | Random 32-byte hex secret for extension device token signing |

### Control Center - LDAP

| Variable | Required | Description |
|----------|----------|-------------|
| `LDAP_URL` | Yes | `ldap://host:389` or `ldaps://host:636` |
| `LDAP_BIND_DN` | Yes | Service account DN for directory search |
| `LDAP_BIND_PASSWORD` | Yes | Service account password |
| `LDAP_USER_SEARCH_BASE` | Yes | Base DN to search for operator accounts |
| `LDAP_USERNAME_ATTRIBUTE` | No | Login attribute. Default: `sAMAccountName` |
| `LDAP_DISPLAY_NAME_ATTRIBUTE` | No | Display name attribute. Default: `displayName` |
| `LDAP_EMAIL_ATTRIBUTE` | No | Email attribute. Default: `mail` |
| `LDAP_ALLOWED_GROUPS` | No | Comma-separated groups allowed to log in. Empty means all |
| `LDAP_INSECURE_SKIP_VERIFY` | No | Skip TLS verification for LDAPS. Not recommended |

## Pinning a Version

Replace `latest` with a specific release tag to lock the stack:

```bash
# .env
UMAI_VERSION=1.2.0
```

Then pull and restart:

```bash
docker compose pull
docker compose up -d
```

## Upgrading

```bash
docker compose pull
docker compose up -d --remove-orphans
```

## Network Security

- `umai-engine` is on the `umai-internal` network only and is unreachable from outside the host.
- `redis` is on `umai-internal` only and is not exposed to the host.
- `umai-service` is on `umai-internal` and `umai-public`, but no host port is exposed.
- Only `umai-control-center` binds a host port (`CC_HOST_PORT`). Put it behind a TLS-terminating reverse proxy in production.

## Reverse Proxy

Example Caddy snippet:

```
console.your-domain.com {
    reverse_proxy umai-control-center:3000
}
```

Example nginx snippet:

```nginx
server {
    listen 443 ssl;
    server_name console.your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```
