from __future__ import annotations

import os
from pathlib import Path

_ENV_LOADED = False


def load_env() -> None:
    """Load the service .env once into process environment."""

    global _ENV_LOADED
    if _ENV_LOADED:
        return
    _ENV_LOADED = True

    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] in ("'", '"') and value[-1] == value[0]:
            value = value[1:-1]
        else:
            comment_index = value.find(" #")
            if comment_index != -1:
                value = value[:comment_index].rstrip()
        os.environ.setdefault(key, value)
