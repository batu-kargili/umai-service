from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

from sqlalchemy import text

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.db import get_engine

logger = logging.getLogger("duvarai.service.repair_oracle_schema")

REQUIRED_COLUMNS = {
    "GUARDRAIL_VERSIONS": {
        "SIGNATURE": "VARCHAR2(256)",
        "KEY_ID": "VARCHAR2(64)",
        "CREATED_BY": "VARCHAR2(128)",
        "APPROVED_BY": "VARCHAR2(128)",
        "APPROVED_AT": "TIMESTAMP WITH TIME ZONE",
    }
}


async def main() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        if conn.dialect.name != "oracle":
            logger.info("Skipping schema repair because dialect is %s", conn.dialect.name)
            return

        for table_name, columns in REQUIRED_COLUMNS.items():
            result = await conn.execute(
                text(
                    "SELECT column_name FROM user_tab_columns "
                    "WHERE table_name = :table_name"
                ),
                {"table_name": table_name},
            )
            existing = {str(row[0]).upper() for row in result}
            for column_name, ddl in columns.items():
                if column_name in existing:
                    continue
                logger.info("Adding %s.%s", table_name, column_name)
                await conn.execute(
                    text(f"ALTER TABLE {table_name} ADD ({column_name} {ddl})")
                )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    asyncio.run(main())
