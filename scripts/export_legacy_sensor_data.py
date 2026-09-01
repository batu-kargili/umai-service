"""Export retained Endpoint Sensor history before its scheduled deletion.

Only the two frozen legacy tables are eligible. Active ADR identity and
credential tables are intentionally excluded.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

from sqlalchemy import MetaData, Table, select

from app.core.db import get_engine

LEGACY_TABLES = ("endpoint_sensor_events", "endpoint_sensor_download_sessions")


def _json(value: Any) -> Any:
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if hasattr(value, "hex"):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


async def export(output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    engine = get_engine()
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "tables": {},
    }
    async with engine.connect() as connection:
        for table_name in LEGACY_TABLES:
            metadata = MetaData()
            table = await connection.run_sync(
                lambda sync_connection, name=table_name, meta=metadata: Table(
                    name, meta, autoload_with=sync_connection
                )
            )
            rows = (await connection.execute(select(table))).mappings()
            target = output / f"{table_name}.jsonl"
            digest = hashlib.sha256()
            count = 0
            with target.open("wb") as stream:
                for row in rows:
                    encoded = (
                        json.dumps({key: _json(value) for key, value in row.items()}, sort_keys=True)
                        + "\n"
                    ).encode("utf-8")
                    stream.write(encoded)
                    digest.update(encoded)
                    count += 1
            manifest["tables"][table_name] = {
                "rows": count,
                "sha256": digest.hexdigest(),
                "file": target.name,
            }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(export(args.output)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
