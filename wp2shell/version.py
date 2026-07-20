"""Passive WordPress version hints from public resources."""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable, Optional, Tuple

from .client import BatchClient, Response, TargetError

_WORDPRESS_RE = re.compile(r"\bWordPress\s+([0-9]+(?:\.[0-9]+){1,3})\b", re.I)
_VERSION_RE = re.compile(r"\b([0-9]+(?:\.[0-9]+){1,3})\b")


@dataclass(frozen=True)
class VersionHint:
    version: str
    source: str
    detail: str
    affected: bool


class _HomepageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.meta_generators = []

    def handle_starttag(self, tag: str, attrs: Iterable[Tuple[str, Optional[str]]]) -> None:
        values = {name.lower(): value for name, value in attrs if value is not None}
        if tag.lower() == "meta" and values.get("name", "").lower() == "generator":
            content = values.get("content")
            if content:
                self.meta_generators.append(content)


def public_version_hints(client: BatchClient, homepage: Optional[Response] = None) -> Tuple[VersionHint, ...]:
    hints = []
    seen = set()

    def add(version: Optional[str], source: str, detail: str) -> None:
        if not version:
            return
        key = (version, source)
        if key in seen:
            return
        seen.add(key)
        hints.append(
            VersionHint(
                version=version,
                source=source,
                detail=detail,
                affected=is_affected_version(version),
            )
        )

    for path, source in (
        ("/wp-json/", "REST API generator"),
        ("/?rest_route=/", "REST API generator (?rest_route=/)"),
    ):
        response = _get(client, path)
        if response is None or response.status >= 400:
            continue
        try:
            body = response.json()
        except json.JSONDecodeError:
            continue
        if isinstance(body, dict):
            generator = body.get("generator")
            if isinstance(generator, str):
                add(_version_from_generator(generator), source, generator)

    response = homepage if homepage is not None else _get(client, "/")
    if response is not None and response.status < 400:
        parser = _HomepageParser()
        parser.feed(response.body)
        for generator in parser.meta_generators:
            add(_version_from_wordpress_text(generator), "HTML generator meta", generator)

    return tuple(hints)


_WP_ASSET_RE = re.compile(r"/(wp-content|wp-includes)/")
_URL_BOUNDARY = ("\"", "'", "`", "(", "<", ">", " ", "\t", "\r", "\n")


def _registrable_domain(host: str) -> str:
    """Last two labels of a host -- enough to tell the target's own domain from a third party's."""
    labels = host.lower().rsplit(":", 1)[0].split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _same_origin_wp_segments(body: str, target_host: str) -> set:
    """wp-content/wp-includes segments `body` references from the target's *own* domain.

    A bare substring match flags third-party asset URLs (a favicon or logo hosted on an unrelated
    WordPress site), so each hit is resolved to its URL's host: root-relative and own-domain
    references count; other domains do not.
    """
    target_domain = _registrable_domain(target_host)
    found = set()
    for match in _WP_ASSET_RE.finditer(body):
        start = max((body.rfind(ch, 0, match.start()) for ch in _URL_BOUNDARY), default=-1)
        host = re.match(r"(?:https?:)?//([\w.\-]+)", body[start + 1 : match.start()])
        if host is None or _registrable_domain(host.group(1)) == target_domain:
            found.add(match.group(1))
    return found


def wordpress_markers(client: BatchClient, homepage: Optional[Response] = None) -> Tuple[str, ...]:
    markers = []

    response = homepage if homepage is not None else _get(client, "/")
    if response is not None and response.status < 400:
        host = urllib.parse.urlsplit(client.base_url).netloc
        segments = _same_origin_wp_segments(response.body, host)
        for segment in ("wp-content", "wp-includes"):
            if segment in segments:
                markers.append(segment)

    for path in ("/wp-json/", "/?rest_route=/"):
        response = _get(client, path)
        if response is None or response.status >= 400:
            continue
        try:
            body = response.json()
        except json.JSONDecodeError:
            body = None
        if isinstance(body, dict) and ("routes" in body or "wp/v2" in response.body):
            if "wp-json" not in markers:
                markers.append("wp-json")

    return tuple(markers)


def is_affected_version(version: str) -> bool:
    parsed = _parse_version(version)
    if parsed is None:
        return False
    return (6, 9, 0) <= parsed <= (6, 9, 4) or (7, 0, 0) <= parsed <= (7, 0, 1)


def version_status(version: str) -> str:
    if is_affected_version(version):
        return "wp2shell affected range"
    return "not in wp2shell affected ranges"


def _get(client: BatchClient, path: str):
    try:
        return client.get(path)
    except TargetError:
        return None


def _version_from_generator(value: str) -> Optional[str]:
    parsed = urllib.parse.urlparse(value)
    for version in urllib.parse.parse_qs(parsed.query).get("v", []):
        normalized = _normalize_version(version)
        if normalized:
            return normalized
    return _version_from_wordpress_text(value)


def _version_from_wordpress_text(value: str) -> Optional[str]:
    match = _WORDPRESS_RE.search(value)
    return _normalize_version(match.group(1)) if match else None


def _normalize_version(value: str) -> Optional[str]:
    match = _VERSION_RE.search(value)
    return match.group(1) if match else None


def _parse_version(version: str) -> Optional[Tuple[int, int, int]]:
    normalized = _normalize_version(version)
    if not normalized:
        return None
    parts = [int(part) for part in normalized.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])
