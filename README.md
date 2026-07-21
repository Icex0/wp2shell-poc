# wp2shell-poc

Independent proof-of-concept for the unauthenticated WordPress REST batch route-confusion
SQL injection associated with Searchlight Cyber's wp2shell advisory.

This repository is not Searchlight Cyber's official checker. `check` confirms the SQLi path,
`read` demonstrates database read, and `shell` opens a plugin-backed command shell either with
supplied administrator credentials or by first exercising the SQLi-to-admin bridge.

![wp2shell — the `shell` command exercising the pre-auth SQLi-to-admin bridge](docs/shell.svg)

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
2. Inside that inner batch, a `GET /wp/v2/posts/999999` item-route request carries posts collection
   query params such as `author_exclude`, `orderby`, and `per_page`. The `999999` ID does not need
   to exist; it is just an unlikely post ID used to match the item route, whose schema does not
   validate those collection-only params. The desync then dispatches the same request under posts
   `get_items()`, where `author_exclude` maps to the `WP_Query` `author__not_in` query var, which
   the vulnerable build interpolates into SQL as a string.

The result is a boolean- and time-based blind SQL injection reachable pre-authentication. This PoC
also includes the UNION fake-post primitive used by the SQLi-to-admin chain.

The RCE path implemented here is:

1. Use UNION fake `wp_posts` rows to render attacker-controlled content through a posts collection.
   The render bridge uses the `/wp/v2/posts/999999` item-route source — the same route the SQLi read
   uses to reach `get_items()`.
2. Use that render to make WordPress create real oEmbed cache posts.
3. Recover those real cache post IDs through the SQLi.
4. In one poisoned batch request, recast those IDs as a customizer changeset, navigation item, and
   request hook shape.
5. Let the same request reach `POST /wp/v2/users`, creating a generated administrator.
6. Log in as that generated administrator and use plugin upload behavior to run a command.

Steps 1–5 are pre-authentication; the command-execution step is authenticated admin plugin upload.

## Requirements

Python 3.8+ and the standard library. No third-party dependencies.

## Usage

Run it from the repository directory:

```
./wp2shell.py <command> <url> [options]
```

Or `pip install .` to get a `wp2shell` command on your `PATH`.

### check — non-destructive vulnerability check

Prints passive WordPress markers and public version hints first, then sends a benign batch marker
probe. A vulnerable batch implementation returns HTTP 207 with the route-confusion marker pattern
`parse_path_failed`, `block_cannot_read`, and `rest_batch_not_allowed`.

The marker probe is based on the WordPress core fix. The malformed `///` request creates
`parse_path_failed`; a `/wp/v2/posts` request acts as a batch-allowed spacer; the
`/wp/v2/block-renderer/...` route is not batch-allowed but returns `block_cannot_read` if its
handler is reached anonymously; `/batch/v1` gives `rest_batch_not_allowed`. On vulnerable builds
the parse error shifts the batch handler arrays out of step, so the spacer request is dispatched
under the block-renderer handler. Fixed builds keep the arrays aligned, so this exact all-three
pattern should not appear for the crafted probe.

By default, `check` stops there and does not send an SQLi payload. Use `--confirm-sqli` when you
also want an active SQLi confirmation. The confirmation tries the UNION read primitive first and
falls back to paired timing probes if UNION reflection is unavailable.

The signals are independent: a version hint is only a hint, the marker pattern shows route
confusion, and `--confirm-sqli` shows a payload reached the database. A WAF can block the payload,
so a failed confirmation doesn't prove the bug is absent.

```
./wp2shell.py check http://target
./wp2shell.py check targets.txt          # scan every URL in the file
```

### read — extract data through SQL injection

```
./wp2shell.py read http://target                      # server fingerprint
./wp2shell.py read http://target --preset users       # user logins and password hashes
./wp2shell.py read http://target --query "SELECT @@version"
```

By default extraction is `--technique auto`, which tries the available methods in this order:

1. **union** — forges a fake `WP_Post` row via `UNION` and reads its title back from the REST
   response as `||HEX(value)||`. The payload uses the same `/wp/v2/posts/999999` source route with
   `orderby=none` and `per_page=500` so the fake row survives as a rendered post. One request per
   value.
2. **error** — `EXTRACTVALUE`/`UPDATEXML` leak ~15 bytes per request, when the target reflects
   MySQL errors (e.g. `WP_DEBUG_DISPLAY` on).
3. **blind** — boolean binary search, ~8 requests per character; reads the posts collection
   `X-WP-Total` header as the true/false signal and needs no reflected value.

Force one with `--technique union|error|blind`. These read paths do not write database rows.

### shell — command execution

With `--user` and `--password`, `shell` logs in with supplied administrator credentials and uses
WordPress plugin upload behavior.

Without credentials, `shell` first runs the pre-auth SQLi-to-admin bridge, logs in as the generated
administrator, then uploads the plugin shell.

```
./wp2shell.py shell http://target --user admin --password '<recovered>' --cmd id
./wp2shell.py shell http://target --user admin --password '<recovered>' -i   # interactive shell
./wp2shell.py shell http://target --cmd id                                   # pre-auth bridge
./wp2shell.py shell http://target -i                                         # pre-auth interactive
```

`shell` uploads a plugin webshell (locked behind a random path and a per-run token) and prints its
path. The uploaded webshell is removed automatically. When the pre-auth bridge creates an
administrator, that generated account is removed automatically after the shell session finishes.

## Options

| Option              | Applies to | Description                                                           |
| ------------------- | ---------- | -------------------------------------------------------------------- |
| `--proxy URL`       | all        | Route traffic through an HTTP proxy (for example, Burp).             |
| `-k` / `--insecure` | all        | Skip TLS certificate verification (for self-signed/untrusted certs). |
| `--timeout N`       | all        | Request timeout in seconds.                                          |
| `--sleep N`         | check      | Delay used by the timing fallback for `--confirm-sqli`.              |
| `--samples N`       | check      | Timing pairs used by the timing fallback for `--confirm-sqli`.       |
| `--confirm-sqli`    | check      | Also send an active SQLi confirmation payload.                       |
| `--preset`          | read       | `fingerprint` or `users`.                                            |
| `--technique`       | read       | `auto` (default), `union` (in-band, forges a fake post), `error` (in-band, needs visible DB errors), or `blind`. |
| `--query`           | read       | A scalar SQL expression to read.                                     |
| `--prefix`          | read       | Database table prefix (default `wp_`).                               |
| `--max-length N`    | read       | Maximum characters read per value (default 128).                     |
| `--user` / `--password` | shell  | Optional admin credentials; omit both to use the pre-auth bridge.   |
| `--cmd`             | shell      | Command to run (omit when using `-i`).                              |
| `-i` / `--interactive` | shell   | Open an interactive shell after deploying.                           |

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
- sergiointel/wp2shell-poc SQLi-to-admin bridge — <https://github.com/sergiointel/wp2shell-poc>
