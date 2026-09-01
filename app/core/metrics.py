"""A small in-process metrics registry, using only stdlib.

Enough to answer "did a limit fire, and how often" without adding a dependency. The
registry is deliberately narrow: counters and gauges keyed by name plus a label tuple,
rendered in Prometheus text format. Observability proper — latency histograms, queue depth,
model cost — is UMA-86 through UMA-89, and is expected to build on this registry rather
than replace it.

Counters live for the process's lifetime and reset when it restarts, which is the normal
contract for a Prometheus-scraped process: the scraper handles resets.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping

_LABEL_ORDER_SEPARATOR = ","


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _key(labels: Mapping[str, str] | None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(name), str(value)) for name, value in labels.items()))


class Registry:
    """Counters and gauges, safe to update from any thread or task."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple[tuple[str, str], ...], float]] = {}
        self._gauges: dict[str, dict[tuple[tuple[str, str], ...], float]] = {}
        self._help: dict[str, str] = {}

    def describe(self, name: str, help_text: str) -> None:
        with self._lock:
            self._help[name] = help_text

    def increment(
        self, name: str, labels: Mapping[str, str] | None = None, amount: float = 1.0
    ) -> None:
        if amount < 0:
            raise ValueError("a counter cannot decrease")
        key = _key(labels)
        with self._lock:
            series = self._counters.setdefault(name, {})
            series[key] = series.get(key, 0.0) + amount

    def set_gauge(
        self, name: str, value: float, labels: Mapping[str, str] | None = None
    ) -> None:
        key = _key(labels)
        with self._lock:
            self._gauges.setdefault(name, {})[key] = float(value)

    def counter_value(self, name: str, labels: Mapping[str, str] | None = None) -> float:
        with self._lock:
            return self._counters.get(name, {}).get(_key(labels), 0.0)

    def gauge_value(self, name: str, labels: Mapping[str, str] | None = None) -> float:
        with self._lock:
            return self._gauges.get(name, {}).get(_key(labels), 0.0)

    def reset(self) -> None:
        """For tests. A running process never resets its own counters."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()

    def render(self) -> str:
        """Prometheus text exposition format."""
        with self._lock:
            counters = {name: dict(series) for name, series in self._counters.items()}
            gauges = {name: dict(series) for name, series in self._gauges.items()}
            help_text = dict(self._help)

        lines: list[str] = []
        for kind, families in (("counter", counters), ("gauge", gauges)):
            for name in sorted(families):
                if name in help_text:
                    lines.append(f"# HELP {name} {help_text[name]}")
                lines.append(f"# TYPE {name} {kind}")
                for key in sorted(families[name]):
                    lines.append(f"{name}{_render_labels(key)} {_render_value(families[name][key])}")
        return "\n".join(lines) + ("\n" if lines else "")


def _render_labels(key: Iterable[tuple[str, str]]) -> str:
    pairs = [f'{name}="{_escape(value)}"' for name, value in key]
    return "{" + _LABEL_ORDER_SEPARATOR.join(pairs) + "}" if pairs else ""


def _render_value(value: float) -> str:
    # Whole numbers render without a decimal point, which is what a counter looks like.
    return str(int(value)) if value == int(value) else repr(value)


registry = Registry()

# Limit enforcement (UMA-83). Named so a breach is greppable in a dashboard query.
LIMIT_REJECTED = "umai_request_limit_rejected_total"
LIMIT_CONCURRENCY_IN_FLIGHT = "umai_request_concurrency_in_flight"
REQUESTS_TOTAL = "umai_requests_total"

registry.describe(LIMIT_REJECTED, "Requests rejected by a rate, body-size, or concurrency limit.")
registry.describe(LIMIT_CONCURRENCY_IN_FLIGHT, "Requests currently in flight per limit class.")
registry.describe(REQUESTS_TOTAL, "Requests admitted past the limit middleware.")
