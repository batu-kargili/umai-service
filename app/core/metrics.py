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


# Latency buckets in seconds. Chosen around the published SLOs rather than a generic
# spread: the deterministic path targets p95 <= 400 ms, so there is resolution either
# side of 0.4, and the LLM path needs headroom out to tens of seconds.
DEFAULT_BUCKETS: tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.75,
    1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0,
)


class _Histogram:
    """Bucket counts, a sum, and a count — the Prometheus histogram shape."""

    __slots__ = ("buckets", "counts", "count", "total")

    def __init__(self, buckets: tuple[float, ...]) -> None:
        self.buckets = buckets
        # One slot per bucket. The +Inf bucket is implied by `count`.
        self.counts = [0] * len(buckets)
        self.count = 0
        self.total = 0.0

    def observe(self, value: float) -> None:
        self.count += 1
        self.total += value
        for index, edge in enumerate(self.buckets):
            if value <= edge:
                self.counts[index] += 1
                # Prometheus buckets are cumulative, but storing them that way would
                # make observe() touch every wider bucket. Storing the exact bucket and
                # accumulating at render time keeps the hot path to one increment.
                break


class Registry:
    """Counters, gauges, and histograms, safe to update from any thread or task."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple[tuple[str, str], ...], float]] = {}
        self._gauges: dict[str, dict[tuple[tuple[str, str], ...], float]] = {}
        self._histograms: dict[str, dict[tuple[tuple[str, str], ...], "_Histogram"]] = {}
        self._buckets: dict[str, tuple[float, ...]] = {}
        self._help: dict[str, str] = {}
        # Cardinality guard state: which label values a metric has already admitted.
        self._seen: dict[tuple[str, str], set[str]] = {}

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

    def declare_histogram(self, name: str, buckets: tuple[float, ...] | None = None) -> None:
        with self._lock:
            self._buckets[name] = tuple(sorted(buckets or DEFAULT_BUCKETS))

    def observe(
        self, name: str, value: float, labels: Mapping[str, str] | None = None
    ) -> None:
        """Record one latency sample, in seconds."""
        key = _key(labels)
        with self._lock:
            buckets = self._buckets.setdefault(name, DEFAULT_BUCKETS)
            series = self._histograms.setdefault(name, {})
            histogram = series.get(key)
            if histogram is None:
                histogram = _Histogram(buckets)
                series[key] = histogram
            histogram.observe(value)

    def histogram_count(self, name: str, labels: Mapping[str, str] | None = None) -> int:
        with self._lock:
            histogram = self._histograms.get(name, {}).get(_key(labels))
            return histogram.count if histogram else 0

    def histogram_sum(self, name: str, labels: Mapping[str, str] | None = None) -> float:
        with self._lock:
            histogram = self._histograms.get(name, {}).get(_key(labels))
            return histogram.total if histogram else 0.0

    def quantile(
        self, name: str, quantile: float, labels: Mapping[str, str] | None = None
    ) -> float | None:
        """Bucket-interpolated quantile, for tests and the ops summary.

        A histogram cannot give an exact quantile — this reports the upper edge of the
        bucket the quantile falls in, which is what a Prometheus `histogram_quantile`
        query approximates too. Returns None when nothing has been observed.
        """
        with self._lock:
            histogram = self._histograms.get(name, {}).get(_key(labels))
            if histogram is None or histogram.count == 0:
                return None
            target = quantile * histogram.count
            seen = 0
            for edge, count in zip(histogram.buckets, histogram.counts):
                seen += count
                if seen >= target:
                    return edge
            return float("inf")

    def bounded_label(self, metric: str, label: str, value: str, cap: int) -> str:
        """Admit a label value only while the metric stays under its cardinality cap.

        Past the cap every new value collapses to "other". Without this a label fed
        from request data — a tenant id, a path — grows one time series per distinct
        value and eventually takes the scrape endpoint, and sometimes the process, down.
        Values already admitted keep reporting, so an established series does not
        disappear because a burst of new ones arrived.
        """
        key = (metric, label)
        with self._lock:
            admitted = self._seen.setdefault(key, set())
            if value in admitted:
                return value
            if len(admitted) >= cap:
                return "other"
            admitted.add(value)
            return value

    def cardinality(self, metric: str, label: str) -> int:
        with self._lock:
            return len(self._seen.get((metric, label), ()))

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
            self._histograms.clear()
            self._seen.clear()

    def render(self) -> str:
        """Prometheus text exposition format."""
        with self._lock:
            counters = {name: dict(series) for name, series in self._counters.items()}
            gauges = {name: dict(series) for name, series in self._gauges.items()}
            histograms = {
                name: {
                    key: (h.buckets, list(h.counts), h.count, h.total)
                    for key, h in series.items()
                }
                for name, series in self._histograms.items()
            }
            help_text = dict(self._help)

        lines: list[str] = []
        for kind, families in (("counter", counters), ("gauge", gauges)):
            for name in sorted(families):
                if name in help_text:
                    lines.append(f"# HELP {name} {help_text[name]}")
                lines.append(f"# TYPE {name} {kind}")
                for key in sorted(families[name]):
                    lines.append(f"{name}{_render_labels(key)} {_render_value(families[name][key])}")

        for name in sorted(histograms):
            if name in help_text:
                lines.append(f"# HELP {name} {help_text[name]}")
            lines.append(f"# TYPE {name} histogram")
            for key in sorted(histograms[name]):
                buckets, counts, count, total = histograms[name][key]
                running = 0
                for edge, bucket_count in zip(buckets, counts):
                    running += bucket_count
                    labels = _render_labels((*key, ("le", _format_edge(edge))))
                    lines.append(f"{name}_bucket{labels} {running}")
                lines.append(f"{name}_bucket{_render_labels((*key, ('le', '+Inf')))} {count}")
                lines.append(f"{name}_sum{_render_labels(key)} {_render_value(total)}")
                lines.append(f"{name}_count{_render_labels(key)} {count}")

        return "\n".join(lines) + ("\n" if lines else "")


def _render_labels(key: Iterable[tuple[str, str]]) -> str:
    pairs = [f'{name}="{_escape(value)}"' for name, value in key]
    return "{" + _LABEL_ORDER_SEPARATOR.join(pairs) + "}" if pairs else ""


def _format_edge(edge: float) -> str:
    # A bucket label must be a stable string across scrapes, or the series changes
    # identity. Integral edges render without a decimal point.
    return str(int(edge)) if edge == int(edge) else repr(edge)


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
