# wp2shell-poc

Independent proof-of-concept for the unauthenticated WordPress REST batch route-confusion
SQL injection associated with Searchlight Cyber's wp2shell advisory.

The unauthenticated primitive reaches the injection through a single endpoint:
`POST /wp-json/batch/v1`.

This repository is not Searchlight Cyber's official checker and does not claim to reproduce
undisclosed wp2shell internals. `check` confirms the SQLi path, `read` demonstrates database
read, and `shell` is an optional post-authentication helper that requires valid administrator
credentials before uploading a plugin webshell.

## Affected versions

Searchlight Cyber's advisory lists these wp2shell RCE exposure ranges:

| Version range | Status |
| ------------- | ------ |
| <= 6.8.5 | Not affected |
| 6.9.0 – 6.9.4 | Affected |
| 7.0.0 – 7.0.1 | Affected |

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

The result is a boolean- and time-based blind SQL injection reachable pre-authentication. This PoC
can use that database read path to recover administrator password hashes. Turning those hashes into
plugin-upload code execution is outside the unauthenticated primitive and depends on obtaining valid
administrator credentials.

Searchlight has not published the final jump from SQLi to pre-auth RCE. That may involve a
database file-write trick such as MySQL `OUTFILE`, or it may be something else in core. This repo
does not include that step.

## Requirements

Python 3.8+ and the standard library. No third-party dependencies.

## Usage

Run it from the repository directory:

```
./wp2shell.py <command> <url> [options]
```

Or `pip install .` to get a `wp2shell` command on your `PATH`.

### check — confirm the vulnerability (safe)

Confirms exploitability with paired differential time delays. It reads no data and changes
nothing. By default it sends three baseline/delayed pairs and decides on the median delta, which
is more reliable on noisy or rate-limited targets than a single timing comparison. If timing
confirmation fails, `check` also looks for passive public WordPress version hints from the REST API
generator, the homepage generator meta tag, and core asset `?ver=` query strings.

```
./wp2shell.py check http://target
```

### read — extract data (blind SQL injection)

```
./wp2shell.py read http://target                      # server fingerprint
./wp2shell.py read http://target --preset users       # user logins and password hashes
./wp2shell.py read http://target --query "SELECT @@version"
```

### shell — post-auth plugin webshell helper

Optional post-exploitation helper. This is not a pre-authentication RCE step: it requires valid
administrator credentials. If `read --preset users` recovers a password hash, supply the recovered
plaintext here after offline cracking.

```
./wp2shell.py shell http://target --user admin --password '<recovered>' --cmd id
./wp2shell.py shell http://target --user admin --password '<recovered>' -i   # interactive shell
```

`shell` uploads a plugin webshell (locked behind a random path and a per-run token) and prints its
path. Remove it when finished — either pass `--cleanup` to have it delete itself after running, or
delete the plugin manually.

## Options

| Option              | Applies to | Description                                                           |
| ------------------- | ---------- | -------------------------------------------------------------------- |
| `--rest-route`      | check, read | Use `/?rest_route=/batch/v1` (for sites without pretty permalinks). |
| `--proxy URL`       | all        | Route traffic through an HTTP proxy (for example, Burp).             |
| `--timeout N`       | all        | Request timeout in seconds.                                          |
| `--sleep N`         | check      | Delay used to confirm the injection.                                 |
| `--samples N`       | check      | Baseline/delayed timing pairs to compare (default 3).                |
| `--preset`          | read       | `fingerprint` or `users`.                                            |
| `--query`           | read       | A scalar SQL expression to read.                                     |
| `--prefix`          | read       | Database table prefix (default `wp_`).                               |
| `--max-length N`    | read       | Maximum characters read per value (default 128).                     |
| `--user` / `--password` | shell  | Admin credentials (plaintext, recovered from the hash).             |
| `--cmd`             | shell      | Command to run (omit when using `-i`).                              |
| `-i` / `--interactive` | shell   | Open an interactive shell after deploying.                           |
| `--cleanup`         | shell      | Delete the webshell from the target when finished.                   |

## Remediation

Update to WordPress 7.0.2, or 6.9.5 if the site is on the 6.9 branch. Until then,
block both `/wp-json/batch/v1` and the `rest_route=/batch/v1` query parameter at
the edge, or require authentication for the batch endpoint via the
`rest_pre_dispatch` filter.

## Legal

For authorized security testing only. Use it exclusively against systems you own or have explicit
written permission to test. No warranty is provided and no liability is accepted for misuse.

## References

- WordPress 7.0.2 release announcement — <https://wordpress.org/news/2026/07/wordpress-7-0-2-release/>
- Searchlight Cyber wp2shell advisory — <https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/>
