from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import uuid

logger = logging.getLogger("duvarai.service.async_jobs")


def schedule_guardrail_job(job_id: uuid.UUID) -> None:
    """Schedule a queued guardrail job for background execution.

    Attaches a task to the running event loop.  Safe to call from any async
    context; logs a warning and does nothing if no loop is running (e.g., in
    tests that don't use async).
    """
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_execute_guardrail_job(job_id), name=f"guardrail-job-{job_id}")
    except RuntimeError:
        logger.warning("async_jobs.schedule.no_loop job_id=%s", job_id)


async def _execute_guardrail_job(job_id: uuid.UUID) -> None:
    """Execute a QUEUED guardrail job and persist the result."""
    # Deferred imports avoid circular dependency (public.py → async_jobs.py)
    from app.core.db import get_sessionmaker, tenant_scope
    from app.core.engine_client import evaluate_engine
    from app.core.errors import ServiceError
    from app.core.events import record_audit_event
    from app.core.license import license_allows_llm_calls, require_active_license
    from app.core.resolver import resolve_environment, resolve_guardrail, resolve_project
    from app.models.db import GuardrailJob
    from app.models.engine import EngineFlags, EngineRequest
    from app.models.public import Decision, PublicGuardAsyncRequest, PublicGuardResponse, TriggeringPolicy

    session_maker = get_sessionmaker()
    tenant_id: uuid.UUID | None = None

    # Transition job → RUNNING
    try:
        async with session_maker() as session:
            async with session.begin():
                job = await session.get(GuardrailJob, job_id)
                if job is None:
                    logger.warning("async_jobs.execute.not_found job_id=%s", job_id)
                    return
                if job.status != "QUEUED":
                    logger.info(
                        "async_jobs.execute.skip status=%s job_id=%s", job.status, job_id
                    )
                    return
                tenant_id = job.tenant_id
                job.status = "RUNNING"
                job.updated_at = dt.datetime.now(dt.timezone.utc)
    except Exception:
        logger.exception("async_jobs.execute.start_error job_id=%s", job_id)
        return

    try:
        # Re-load job fields inside the execution block
        async with session_maker() as session:
            async with session.begin():
                job = await session.get(GuardrailJob, job_id)
                if job is None:
                    return
                tenant_id = job.tenant_id
                environment_id = job.environment_id
                project_id = job.project_id
                guardrail_id = job.guardrail_id
                guardrail_version = job.guardrail_version
                phase = job.phase
                request_id = str(job.request_id)
                request_payload_json = job.request_payload_json
                webhook_url = job.webhook_url
                webhook_secret = job.webhook_secret

        # Validate license & resolve entities
        allow_llm_calls = False
        async with session_maker() as session:
            async with session.begin():
                async with tenant_scope(session, str(tenant_id)):
                    license_row = await require_active_license(session, tenant_id)
                    allow_llm_calls = license_allows_llm_calls(license_row)
                    await resolve_environment(session, tenant_id, environment_id)
                    await resolve_project(session, tenant_id, environment_id, project_id)
                    await resolve_guardrail(
                        session, tenant_id, environment_id, project_id, guardrail_id
                    )

        # Build and dispatch engine request
        request_payload = PublicGuardAsyncRequest.model_validate(json.loads(request_payload_json))
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        engine_request = EngineRequest(
            request_id=request_id,
            timestamp=timestamp,
            tenant_id=str(tenant_id),
            environment_id=environment_id,
            project_id=project_id,
            guardrail_id=guardrail_id,
            guardrail_version=guardrail_version,
            phase=phase,
            input=request_payload.input,
            timeout_ms=request_payload.timeout_ms,
            flags=EngineFlags(allow_llm_calls=allow_llm_calls),
        )
        engine_response = await evaluate_engine(engine_request)

        # Convert to public response shape
        triggering_policy = None
        if engine_response.triggering_policy:
            triggering_policy = TriggeringPolicy(
                policy_id=engine_response.triggering_policy.policy_id,
                type=engine_response.triggering_policy.type,
                status=engine_response.triggering_policy.status,
            )
        public_response = PublicGuardResponse(
            request_id=engine_response.request_id,
            decision=Decision(
                action=engine_response.decision.action,
                allowed=engine_response.decision.allowed,
                severity=engine_response.decision.severity,
                reason=engine_response.decision.reason,
            ),
            category=None,
            triggering_policy=triggering_policy,
            output_modifications=engine_response.output_modifications,
            latency_ms=int(engine_response.latency_ms.total),
            errors=[err.model_dump() for err in engine_response.errors],
        )

        # Persist audit event + mark job COMPLETED
        async with session_maker() as session:
            async with session.begin():
                async with tenant_scope(session, str(tenant_id)):
                    await record_audit_event(
                        session,
                        tenant_id=tenant_id,
                        environment_id=environment_id,
                        project_id=project_id,
                        guardrail_id=guardrail_id,
                        guardrail_version=guardrail_version,
                        engine_response=engine_response,
                        request_payload=None,
                    )
                    row = await session.get(GuardrailJob, job_id)
                    if row:
                        row.status = "COMPLETED"
                        row.response_payload_json = public_response.model_dump_json()
                        now = dt.datetime.now(dt.timezone.utc)
                        row.completed_at = now
                        row.updated_at = now

        logger.info("async_jobs.execute.completed job_id=%s", job_id)

        # Fire webhook if configured
        if webhook_url:
            await _send_webhook(job_id, webhook_url, webhook_secret, public_response)

    except ServiceError as exc:
        logger.warning(
            "async_jobs.execute.service_error job_id=%s type=%s msg=%s",
            job_id,
            exc.error_type,
            exc.message,
        )
        await _mark_failed(job_id, tenant_id, f"{exc.error_type}: {exc.message}")
    except Exception:
        logger.exception("async_jobs.execute.failed job_id=%s", job_id)
        await _mark_failed(job_id, tenant_id, "Unexpected error during job execution")


async def _mark_failed(
    job_id: uuid.UUID,
    tenant_id: uuid.UUID | None,
    error_message: str,
) -> None:
    from app.core.db import get_sessionmaker, tenant_scope
    from app.models.db import GuardrailJob

    try:
        session_maker = get_sessionmaker()
        async with session_maker() as session:
            async with session.begin():
                if tenant_id is not None:
                    async with tenant_scope(session, str(tenant_id)):
                        row = await session.get(GuardrailJob, job_id)
                        if row:
                            _apply_failed(row, error_message)
                else:
                    row = await session.get(GuardrailJob, job_id)
                    if row:
                        _apply_failed(row, error_message)
    except Exception:
        logger.exception("async_jobs.mark_failed.error job_id=%s", job_id)


def _apply_failed(row, error_message: str) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    row.status = "FAILED"
    row.error_message = error_message[:2000]
    row.completed_at = now
    row.updated_at = now


async def _send_webhook(
    job_id: uuid.UUID,
    webhook_url: str,
    webhook_secret: str | None,
    response,
) -> None:
    import hashlib
    import hmac as _hmac

    import httpx

    from app.core.settings import settings

    try:
        body = response.model_dump_json().encode("utf-8")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if webhook_secret:
            sig = _hmac.new(
                webhook_secret.encode("utf-8"), body, hashlib.sha256
            ).hexdigest()
            headers["X-Umai-Signature"] = f"sha256={sig}"

        async with httpx.AsyncClient(
            timeout=settings.async_job_webhook_timeout_seconds
        ) as client:
            resp = await client.post(webhook_url, content=body, headers=headers)
            logger.info(
                "async_jobs.webhook.sent job_id=%s url=%s status=%s",
                job_id,
                webhook_url,
                resp.status_code,
            )
    except Exception as exc:
        logger.warning("async_jobs.webhook.failed job_id=%s url=%s error=%s", job_id, webhook_url, exc)
