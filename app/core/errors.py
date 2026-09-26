from __future__ import annotations


class ServiceError(Exception):
    def __init__(
        self,
        error_type: str,
        message: str,
        status_code: int,
        retryable: bool = False,
        details: dict | None = None,
    ):
        super().__init__(message)
        self.error_type = error_type
        self.message = message
        self.status_code = status_code
        self.retryable = retryable
        self.details = details

    def to_dict(self) -> dict:
        payload = {
            "type": self.error_type,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.details is not None:
            payload["details"] = self.details
        return payload
