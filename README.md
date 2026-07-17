# wp2shell-poc

Proof-of-concept for an unauthenticated SQL injection in WordPress core that chains to remote
code execution, via REST batch route confusion (CVE-2026-63030).

The exploit needs no credentials and no configuration beyond a reachable target. It reaches the
injection through a single endpoint: `POST /wp-json/batch/v1`.

The finding itself is that unauthenticated SQL injection — `check` confirms it and `read`
demonstrates arbitrary database read. The `shell` command is optional post-exploitation
(recovered admin credentials → plugin upload → command execution), included to demonstrate full
impact; it is not the vulnerability.

## Affected versions

| Branch | Affected      | Fixed in |
| ------ | ------------- | -------- |
| 6.9.x  | 6.9.0 – 6.9.4 | 6.9.5    |
| 7.0.x  | 7.0.0 – 7.0.1 | 7.0.2    |

Versions before 6.9.0 are not affected by this chain.

## How it works

The REST batch endpoint (`/batch/v1`) is unauthenticated and runs several sub-requests in one
call, relying on each sub-request being validated and permission-checked on its own.

`serve_batch_request_v1()` builds two parallel arrays — `$matches` (the matched handler per
sub-request) and `$validation` (the validation result per sub-request) — then indexes both by
the same offset when dispatching. A sub-request whose path fails `wp_parse_url()` is appended to
`$validation` but not to `$matches`, so the arrays fall out of step and a sub-request is
dispatched under a **different** sub-request's handler. That is the route confusion.

The PoC nests the primitive twice:

1. A `POST /wp/v2/posts` request that carries a `requests` body is dispatched under the batch
   handler itself. Having been validated as a posts request, its `requests` list is never checked
   against the batch schema, so its sub-requests may use `GET` — the method allow-list is
   bypassed.
2. Inside that inner batch, a `GET /wp/v2/users` request carrying an `author_exclude` string
   (the users schema has no such parameter, so the value passes validation untouched) is
   dispatched under posts `get_items()`. There `author_exclude` maps to the `WP_Query`
   `author__not_in` query var, which the vulnerable build interpolates into SQL as a string.

The result is a boolean- and time-based blind SQL injection reachable pre-authentication. With
database read access the administrator password hash can be recovered; once cracked, admin access
yields code execution through a plugin upload.

## Requirements

Python 3.8+ and the standard library. No third-party dependencies.

## Usage

Run it from the repository directory:

```
./wp2shell.py <command> <url> [options]
```

Or `pip install .` to get a `wp2shell` command on your `PATH`.

### check — confirm the vulnerability (safe)

Confirms exploitability with a differential time delay. It reads no data and changes nothing.

```
./wp2shell.py check http://target
```

### read — extract data (blind SQL injection)

```
./wp2shell.py read http://target                      # server fingerprint
./wp2shell.py read http://target --preset users       # user logins and password hashes
./wp2shell.py read http://target --query "SELECT @@version"
```

### shell — execute a command (remote code execution)

Optional post-exploitation. Requires valid administrator credentials; the injection recovers the
password *hash*, so supply the recovered plaintext here.

```
./wp2shell.py shell http://target --user admin --password '<recovered>' --cmd id
./wp2shell.py shell http://target --user admin --password '<recovered>' -i   # interactive shell
```

`shell` uploads a plugin webshell (locked behind a random path and a per-run token) and prints its
path. Remove it when finished.

## Options

| Option              | Applies to | Description                                                           |
| ------------------- | ---------- | -------------------------------------------------------------------- |
| `--rest-route`      | all        | Use `/?rest_route=/batch/v1` (for sites without pretty permalinks).  |
| `--proxy URL`       | all        | Route traffic through an HTTP proxy (for example, Burp).             |
| `--timeout N`       | all        | Request timeout in seconds.                                          |
| `--sleep N`         | check      | Delay used to confirm the injection.                                 |
| `--preset`          | read       | `fingerprint` or `users`.                                            |
| `--query`           | read       | A scalar SQL expression to read.                                     |
| `--prefix`          | read       | Database table prefix (default `wp_`).                               |
| `--max-length N`    | read       | Maximum characters read per value (default 128).                     |
| `--user` / `--password` | shell  | Admin credentials (plaintext, recovered from the hash).             |
| `--cmd`             | shell      | Command to run (omit when using `-i`).                               |
| `-i` / `--interactive` | shell   | Open an interactive shell after deploying.                           |

## Remediation

Update to WordPress 6.9.5 or 7.0.2. Until then, block both `/wp-json/batch/v1` and the
`rest_route=/batch/v1` query parameter at the edge, or require authentication for the batch
endpoint via the `rest_pre_dispatch` filter.

## Legal

For authorized security testing only. Use it exclusively against systems you own or have explicit
written permission to test. The author accepts no liability for misuse.

## References

- WordPress 7.0.2 release announcement — <https://wordpress.org/news/2026/07/wordpress-7-0-2-release/>
- CVE-2026-63030
