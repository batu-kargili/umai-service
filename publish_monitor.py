import asyncio
import datetime as dt
import json
import uuid

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.db import tenant_scope
from app.core.redis import get_redis
from app.core.settings import settings
from app.core.snapshot_signing import pack_snapshot_record, sign_snapshot
from app.core.snapshots import build_snapshot_key, publish_snapshot
from app.models.db import Guardrail, GuardrailVersion

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
ENV = "test"
PROJ = "m4-sensor-test"
GR = "m4-proxy-policy"
VER = 1

SRC = ("tester", "gr-tr-regulated-telecom-sovereign-shield-bb")


async def main() -> None:
    engine = create_async_engine(settings.database_url)
    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        # Borrow the published guardrail's snapshot shape for structural validity.
        async with session.begin():
            async with tenant_scope(session, str(TENANT)):
                src = await session.get(
                    GuardrailVersion, (TENANT, ENV, SRC[0], SRC[1], 1)
                )
                snap = json.loads(src.snapshot_json)

        # Keep the real policy config (empty config = "configuration missing" =>
        # fail-closed block), but run it in MONITOR mode. In MONITOR mode the
        # engine observes/records without enforcing, and the context-aware
        # policy's llm-disabled error is downgraded to ALLOW, so traffic flows
        # through while every prompt is still logged as a transaction.
        snap["guardrail_id"] = GR
        snap["version"] = VER
        snap["mode"] = "MONITOR"

        signature, key_id = sign_snapshot(snap)
        snap_json = json.dumps(snap, separators=(",", ":"), ensure_ascii=True)

        async with session.begin():
            async with tenant_scope(session, str(TENANT)):
                row = await session.get(
                    GuardrailVersion, (TENANT, ENV, PROJ, GR, VER)
                )
                if row is None:
                    row = GuardrailVersion(
                        tenant_id=TENANT,
                        environment_id=ENV,
                        project_id=PROJ,
                        guardrail_id=GR,
                        version=VER,
                        created_by="m4-monitor",
                    )
                    session.add(row)
                row.snapshot_json = snap_json
                row.signature = signature
                row.key_id = key_id
                row.approved_by = "m4-monitor"
                row.approved_at = dt.datetime.now(dt.timezone.utc)

                g = await session.get(Guardrail, (TENANT, ENV, PROJ, GR))
                if g is not None:
                    g.current_version = VER

        # The engine fetches snapshots from its Redis store, so publish there too.
        redis_key = build_snapshot_key(str(TENANT), ENV, PROJ, GR, VER)
        redis = get_redis()
        await publish_snapshot(
            redis, redis_key, pack_snapshot_record(snap, signature, key_id)
        )

        print(f"published {GR} v{VER} mode=MONITOR -> db + redis ({redis_key})")


asyncio.run(main())
