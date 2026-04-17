from __future__ import annotations

import contextvars
import logging

from app.core.settings import settings

_request_id = contextvars.ContextVar("request_id", default="-")
_record_factory = logging.getLogRecordFactory()


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id.get()
        return True


def set_request_id(value: str) -> contextvars.Token:
    return _request_id.set(value)


def reset_request_id(token: contextvars.Token) -> None:
    _request_id.reset(token)


def configure_logging() -> None:
    def record_factory(*args, **kwargs):  # type: ignore[no-untyped-def]
        record = _record_factory(*args, **kwargs)
        if not hasattr(record, "request_id"):
            record.request_id = _request_id.get()
        return record

    level_name = settings.log_level.upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.setLogRecordFactory(record_factory)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s request_id=%(request_id)s %(message)s",
    )
    logging.getLogger().addFilter(RequestIdFilter())
    logging.getLogger("httpx").setLevel(logging.WARNING)
