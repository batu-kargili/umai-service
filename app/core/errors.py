from __future__ import annotations


class ServiceError(Exception):
    def __init__(self, error_type: str, message: str, status_code: int, retryable: bool = False):
        super().__init__(message)
        self.error_type = error_type
        self.message = message
        self.status_code = status_code
        self.retryable = retryable

    def to_dict(self) -> dict:
        return {
            "type": self.error_type,
            "message": self.message,
            "retryable": self.retryable,
        }
