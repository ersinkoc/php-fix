# php-fix

[![CI](https://github.com/ersinkoc/php-fix/actions/workflows/ci.yml/badge.svg)](https://github.com/ersinkoc/php-fix/actions/workflows/ci.yml)

One-line emergency mitigation for **php2shell** (**CVE-2026-109618** / **CVE-2026-109619**), two critical unauthenticated PHP RCE bugs (CVSS v4.0 9.2), for servers that can't be patched right away.

> [!IMPORTANT]
> **The fix is out. Update PHP first:** **8.5.12, 8.4.27, 8.3.36 and 8.2.35** (released 21 October 2026). Distro builds may keep the old upstream number with the fix backported, so check your distro's tracker. PHP 8.1 and older get no php.net fix.
> The PHP team says updating is the only complete mitigation. This script is for the time until you can.

It sets `session.upload_progress.enabled = Off` across every PHP installation on a Linux server: distro packages, control panels, multiple PHP versions, PHP-FPM pools and Apache mod_php. On **unpatched PHP 8.5** it also sets `fatal_error_backtraces = Off`. Then it verifies the result through the CLI and FPM binaries and every running FPM pool. Read-only modes check patch status against the fixed versions (`--check`), sweep for signs of compromise (`--audit`) and print WAF rules for the multipart path (`--waf-print`).

## What the two bugs are (from the official advisories)

| | [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w): RCE via OOM corruption | [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp): RCE via stale global state |
|---|---|---|
| Bug | PHP leaves the request with `longjmp()` on out-of-memory while request memory is only partly initialized. Shutdown then trusts it. | Global state survives the request that owned it. A later request on the same worker reads it before startup resets it. |
| How it's reached | Mainly **multipart parsing**: bodies without a usable length, unlimited headers per part, empty file fields and nested names exhaust `memory_limit` while staying under `post_max_size` | **Producer:** a fatal error or OOM (on 8.5, `fatal_error_backtraces`). **Consumer:** session upload progress, or a warning from a per-request INI override |
| Confirmed against | Apache mod_php (full RCE). FPM, FrankenPHP and LSAPI are likely affected | mod_php, plus FPM via the upload-progress path |
| What php-fix does | Nothing in PHP config can close it. Block multipart at the edge (`--waf-print`) | `session.upload_progress.enabled = Off`, plus `fatal_error_backtraces = Off` on PHP 8.5 |

Neither setting is complete. They close the confirmed paths, not every variant. **Patch.**

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash
```

### Verified install (recommended for production / fleets)

Piping `main` into `sudo bash` means trusting whatever is on `main` at that moment. For production, use a release instead. Every release is built by GitHub Actions and ships with a `SHA256SUMS` file and a signed [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations):

```bash
V=v1.5.0
curl -fsSLO https://github.com/ersinkoc/php-fix/releases/download/$V/install.sh
curl -fsSLO https://github.com/ersinkoc/php-fix/releases/download/$V/SHA256SUMS
sha256sum -c SHA256SUMS                                      # integrity
gh attestation verify install.sh --repo ersinkoc/php-fix     # built from this repo by CI (optional, needs gh)
sudo bash install.sh
```

## Modes

| Command | Changes the server? | What it does |
|---|---|---|
| `sudo bash install.sh` | **Yes** (with backups) | Applies the mitigation, reloads services gracefully, verifies |
| `... --dry-run` | No | Shows what the default mode would change |
| `... --no-restart` | Yes, without reloads | Applies the changes but doesn't reload services; reload them yourself later |
| `... --check` | No | **PATCHED** / **UNPATCHED** / **EOL, no patch** / unknown against 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 for every PHP binary, **every running FPM pool (live)** and **every running Docker container** (`docker exec php`). Also detects distro backports via the package changelog, and warns about held / version-locked PHP packages (`apt-mark hold`, `dnf versionlock`) that would silently skip the update |
| `... --audit[=HOURS]` | No | Heuristic indicator-of-compromise sweep (default: last 48 h). Runs at lowest CPU/IO priority |
| `... --waf-print` | No | Prints rules for the multipart path: ModSecurity, nginx, Apache, LiteSpeed/.htaccess, Caddy/FrankenPHP, HAProxy, Cloudflare |
| `... --revert[=STAMP]` | **Yes** | Restores the backups of the last run (or of the run `STAMP`, e.g. `20261021-120000`) and removes the mod_php drop-in |
| `... --probe=URL` | No (5 harmless HTTP requests) | **From outside:** does multipart (POST, PUT, mixed-case) still reach this PHP URL, or is it blocked at the edge? No root needed; run it from your laptop |
| `... --user-ini=DIR` | Only `DIR/.user.ini` | **Shared hosting without root:** sets it in the site's `.user.ini` (PHP-FPM / CGI / LiteSpeed). Run as the site user |
| `... --check --json` | No | Same as `--check`, as one JSON document for fleet tooling (Ansible, Salt, SIEM) |

With curl, pass options like this: `curl -fsSL .../install.sh | sudo bash -s -- --check`

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. `--check`: everything patched. `--audit`: nothing flagged |
| `1` | A step failed, or the setting is still On somewhere. `--check`: something is unpatched or its status is unknown |
| `2` | A PHP **older than 5.4** was found. This mitigation **cannot** protect it |
| `3` | `--audit` found items to review |

`--probe` uses its own codes: `0` = multipart is blocked before PHP, `1` = it reaches the app, `2` = no answer.

## Safety: designed not to break servers

- **Backups:** every file is backed up as `<file>.bak-YYYYMMDD-HHMMSS` before it changes, and `--revert` puts the originals back byte-for-byte. Revert is tested in CI.
- **Graceful reloads:** services get `systemctl reload-or-restart`. PHP-FPM and Apache reload gracefully, so in-flight requests finish, and LiteSpeed uses its own graceful restart. Worker processes are never killed directly.
- **Apache config is always tested:** Apache is never reloaded with a failing config.
  - If the config already fails before the script runs, Apache isn't touched at all.
  - If the new drop-in makes the test fail, the drop-in is removed again.
- **Read-only modes really are read-only:** `--dry-run`, `--check`, `--audit` and `--waf-print` change nothing. `--audit` runs under `nice -n 19` and `ionice -c3`, and caps log reads at 200k lines per file.
- **No writes through symlinks** and no writes in directories that aren't root-owned or that are group/world-writable. This blocks symlink-planting attacks against the root process.
- **Idempotent:** running the script again skips everything that's already fixed.
- **Nothing your apps rely on breaks:** normal file uploads keep working. See [Side effects](#side-effects).

## What the default mode does

1. **Finds every `php.ini`** under the usual locations (`/etc`, `/usr/local/etc`, `/usr/local/lib`, `/usr/local/php*`, `/opt/cpanel`, `/opt/alt`, `/opt/plesk/php`, `/opt/remi`, `/etc/opt/remi`, `/www/server/php`, `/usr/local/lsws`), plus the one `php --ini` reports.
2. **Sets `session.upload_progress.enabled = Off`** in each one. It replaces an existing (commented or active) line, adds the setting under `[Session]`, or appends a `[Session]` block.
3. **Fixes overrides** in additional `.ini` files (`conf.d/*.ini`) that turn the setting back on.
4. **Locks every PHP-FPM pool.** Without this, a `.user.ini` with `On` overrides the php.ini `Off`.
   - Any existing `php_value` / `php_flag` for this directive becomes `php_admin_flag[session.upload_progress.enabled] = off`.
   - Pools with no setting at all get that line added.
   - Each FPM binary runs `php-fpm -t` before and after the change. If a config that passed before fails afterwards, the pool files are restored on the spot.

   Control panels (cPanel, Plesk) may regenerate pool files later. Re-run the script after panel PHP changes. The php.ini setting stays in place either way.
5. **PHP 8.5 only, unpatched builds only:** writes `zz-php2shell.ini` with `fatal_error_backtraces = Off` into that binary's own `conf.d`. It leaves `php.ini` untouched, and `--revert` removes the file. On 8.5 this setting defaults to On and is the confirmed CVE-2026-109619 producer. Turning it off only drops the backtrace from fatal error messages.
6. **Hardens Apache mod_php.** If mod_php is loaded, it drops in `zz-php2shell.conf` with `php_admin_flag session.upload_progress.enabled off`, which `.htaccess` cannot override.
   - Debian / Ubuntu: `/etc/apache2/conf-available/` + `a2enconf`
   - RHEL family: `/etc/httpd/conf.d/`
   - cPanel EA4: `/etc/apache2/conf.d/`
7. **Reloads services gracefully**: `php*-fpm`, `ea-php*`, `plesk-php*`, `apache2` / `httpd`, LiteSpeed.
8. **Verifies at three levels:**
   - every PHP **CLI** binary (`ini_get`)
   - every **php-fpm** binary (`php-fpm -i`), which catches an FPM that reads a different ini
   - **every running FPM pool, live over FastCGI.** The script speaks FastCGI to each pool's socket or port with a tiny built-in client, runs a one-line `ini_get` script from `/run`, and reads the value that pool really serves, pool overrides included. It needs no `cgi-fcgi` and puts no file in any web root. Chrooted or `open_basedir` pools are reported as "not verified".
9. **Checks the PHP version** of every binary it finds:
   - **PHP < 5.4**: the setting doesn't exist there, but the multipart parser is still exposed. The script reports *NOT PROTECTED* and exits `2`.
   - **PHP < 8.2 (EOL branches)**: php.net doesn't patch these. Your vendor might backport the fix (RHEL, Ubuntu Pro, Debian LTS, TuxCare, CloudLinux), and `--check` detects that from the package changelog. Otherwise, block or limit multipart at the proxy/WAF (`--waf-print`) and upgrade.

## `--audit`: what it looks at

This is a heuristic sweep, not proof either way. Every finding needs a human to look at it.

- PHP / `.htaccess` / `.user.ini` files changed in web roots within the window (listed for review; CMS updates are normal noise)
- Webshell-like code in those files (`eval(base64_decode(...))`, `system($_POST...)`, and similar)
- `.htaccess` / `.user.ini` files that turn upload progress back on
- Shells or interpreters (`sh`, `bash`, `nc`, `python`, `perl`, `curl`, `wget`, …) whose parent is PHP or the web server. Some are legitimate, e.g. `mail()` calling `sh -c sendmail`.
- Session files containing `upload_progress_` data, meaning the vulnerable code path was exercised
- Recently changed cron jobs
- Busiest POST-to-`.php` clients in the current access logs (context only)
- If your access logs record `Content-Type` (see the logging snippets in `--waf-print`): the top multipart senders, and every **multipart request answered with 500–504**. A worker crashing under multipart is the strongest exploitation signal you can get from logs.
- **PHP / web worker crashes** (`SIGSEGV`, `exited on signal 11`, kernel `segfault at … php-fpm`) in FPM and Apache logs and the kernel log. Memory-corruption exploits usually crash workers while they are being tuned.
- PHP files dropped in `/tmp`, `/var/tmp` or `/dev/shm`
- Reverse-shell command lines on any process (`/dev/tcp/`, `mkfifo … nc`, `nc -e`, `bash -i`, `socat … exec`, `fsockopen`, `pty.spawn`)
- Shells or interpreters running as a web user (`www-data`, `apache`, `nginx`, `nobody`, …) and detached from their parent (double-forked)
- Shells or interpreters holding network connections (`ss`)
- Running PHP Docker containers, which this script cannot reach

If `ps` or `ss` is missing (e.g. minimal container images), the audit says which checks it skipped.

## Tested

CI runs [`tests/run.sh`](tests/run.sh) on every push. It installs real PHP from the distro packages and exercises every mode end to end:

| Distro | PHP | Notes |
|---|---|---|
| Debian 13 (trixie) | 8.4 | php-fpm + Apache mod_php |
| Debian 12 (bookworm) | 8.2 | php-fpm + Apache mod_php |
| Ubuntu 24.04 | 8.3 | php-fpm + Apache mod_php |
| AlmaLinux 9 | 8.0 (EOL) | php-fpm + httpd |

The tests cover:
- **Fix and revert:**
  - dry-run changes nothing; php.ini, `conf.d` and FPM pool overrides are fixed; a second run is idempotent
  - a pool with no setting gets `php_admin_flag` and `php-fpm -t` still passes
  - a non-FPM config containing `listen =` is left alone
  - `--revert` restores php.ini and the pool files byte-for-byte and leaves Apache valid
  - world-writable directories are refused
- **Can it be re-enabled?** Each test is a real HTTP request that returns `'0'`:
  - **mod_php:** a `.htaccess` with `php_flag … on` cannot turn it back on
  - **nginx + PHP-FPM:** a `.user.ini` with `On` cannot turn it back on
- **`--waf-print` rules, run in real Apache and nginx** (configtest passes in both, including the logging snippets):
  - multipart POST, multipart **PUT** and a mixed-case `Content-Type` get `403`, as does the prefix trick `/wp-admin/async-upload.php-evil.php`
  - the allowlisted path, urlencoded POSTs and JSON POSTs pass
  - on Apache: a subfolder `.htaccess` with `RewriteEngine On` + `Require all granted` cannot bypass the rule, and neither can a vhost with its own rewrite rules
- **Live pool verification:**
  - `--check` and the fix itself read the live value from running FPM pools over FastCGI, over a unix socket and over TCP
  - a pool added later with `php_admin_value[…] = 1` is reported as mitigation off
  - `--check --json` produces valid JSON
- **`--probe`:** reports `0` (blocked) against Apache with the rule, and `1` (reaches PHP) without it
- **`--user-ini`:** writes `.user.ini` as the site user, is idempotent, and is refused as root
- **PHP 8.5 (stub binary):** `--check` flags `fatal_error_backtraces` On; the fix writes the `conf.d` drop-in only on unpatched 8.5, verifies it, is idempotent, and `--revert` removes it
- **Fixed versions:** `--check` classifies real distro PHP as PATCHED / UNPATCHED / EOL (Debian trixie already ships 8.4.27)
- **`--audit` and `--check`:**
  - `--audit` flags a planted webshell, a worker `SIGSEGV` log line, a PHP file in `/tmp`, a reverse-shell command line, and a multipart request answered with `502` in a `Content-Type`-logging access log
  - `--audit` output stays clean when file names carry terminal escapes (ESC, 8-bit and UTF-8 C1)
  - `--check` runs; the EOL warning and the `< 5.4` exit `2` path are tested with stub binaries

Run the tests locally with: `docker run --rm -v "$PWD:/src:ro" debian:trixie bash /src/tests/run.sh`

### Supported environments

| Environment | Paths covered |
|---|---|
| Debian / Ubuntu (ondrej/php) | `/etc/php/*/{fpm,cli,apache2}/php.ini` |
| RHEL / Alma / Rocky / CentOS / Remi | `/etc/php.ini`, `/etc/opt/remi/*`, `/opt/remi/*` |
| cPanel EasyApache | `/opt/cpanel/ea-php*/root/etc/php.ini` |
| CloudLinux alt-php | `/opt/alt/php*/etc/php.ini` |
| Plesk | `/opt/plesk/php/*/etc/php.ini` |
| aaPanel / BT | `/www/server/php/*/etc/php.ini` |
| DirectAdmin / custom builds | `/usr/local/php*`, `/usr/local/lib/php.ini` |
| LiteSpeed / OpenLiteSpeed | `/usr/local/lsws/lsphp*/etc/php/*/litespeed/php.ini` |

Requirements: bash 4+ (CentOS 7's bash 4.2 works), GNU coreutils / `sed` / `find` / `grep`, root (only `--check`, `--audit` and `--waf-print` work without root; `--audit` is less complete then).

## Side effects

Disabling upload progress only stops PHP from writing upload progress data into `$_SESSION`. **Normal file uploads keep working.** Only applications that poll `$_SESSION['upload_progress_*']` to draw upload progress bars lose that feature until you turn it back on.

## Manual verification

```bash
php -i | grep session.upload_progress.enabled          # CLI
php-fpm8.3 -i | grep session.upload_progress.enabled   # FPM's php.ini (adjust binary name)
```

For the real web SAPI, including FPM pool settings, put `<?php var_export(ini_get('session.upload_progress.enabled'));` in a temporary file and open it in a browser. `''` or `'0'` means Off. **Delete the file afterwards.**

## Shared hosting (no root)

If you only have SSH or FTP access to your own site:

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | bash -s -- --user-ini=$HOME/public_html
```

- **PHP-FPM / CGI / LiteSpeed:** this writes `session.upload_progress.enabled = 0` into `.user.ini` with a backup. PHP picks it up within 5 minutes (`user_ini.cache_ttl`).
- **Apache mod_php ignores `.user.ini`.** There, add `php_flag session.upload_progress.enabled off` to `.htaccess` instead, and load the site right after: under PHP-FPM that line causes a 500 error.
- **No SSH at all?** Many panels have a php.ini / "PHP settings" editor. Set the same value there.
- **Verify** with a temporary `<?php var_export(ini_get('session.upload_progress.enabled'));` file. It must print `'0'` or `''`. Delete the file afterwards.
- **Ask your host to update PHP** to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. This setting doesn't cover CVE-2026-109618.

## Verify from outside

After adding edge rules, check them from another machine. The test needs no root and sends no exploit payload:

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | bash -s -- --probe=https://example.com/index.php
```

It compares a multipart POST, a multipart PUT and a mixed-case `Content-Type` against a normal urlencoded POST. Point it at a PHP route that isn't on your upload allowlist. For a deeper reachability test with before/after-patch baselines, see [php2shell-scan](https://github.com/0xrsydn/php2shell-scan).

## Updating PHP

`--check` prints the right command for your system. Typical commands:

```bash
# Debian / Ubuntu (distro packages or the ondrej/sury repositories)
apt-get update && apt-get install --only-upgrade $(dpkg-query -W -f='${binary:Package}\n' '*php*')
# RHEL / Alma / Rocky / Fedora / Remi / cPanel EA4
dnf upgrade '*php*'        # or: yum update '*php*'
# Docker: rebuild on the fixed official tag, e.g. php:8.4.27-fpm, php:8.3.36-apache
```

Then **restart every PHP worker**: PHP-FPM, Apache with mod_php, LiteSpeed lsphp. Old workers keep running the old code until they're replaced. Control panels (Plesk, CloudLinux alt-php, DirectAdmin CustomBuild) update PHP from their own updaters. Run `--check` afterwards.

## Blocking multipart before PHP (CVE-2026-109618)

The OOM bug is reached mainly through PHP's multipart parser, and no PHP setting closes it. The advisory recommends blocking multipart at the frontend if the application doesn't need it. Run `--waf-print` for ready-made rules.

- **Match every method, not just POST.** PHP 8.4's `request_parse_body()` parses multipart on PUT and PATCH too.
- **Match `multipart` anywhere in `Content-Type`, case-insensitively.** Don't anchor it to `^multipart/form-data`.
- **Allowlist exact script paths only** (`^/wp-admin/async-upload\.php$`), never prefixes like `^/upload`.
- **Apache:** use the server-wide `<Location "/"> <If …> Require all denied` version. A bare top-level `<If>` or a `.htaccess` rewrite can be overridden by a subfolder `.htaccess`. We tested both bypasses.
- **nginx:** put the guard at `server {}` level, so every route that ends up in PHP is covered.
- **CDN / WAF:** it only protects traffic that goes through it. Restrict the origin to the CDN's IP ranges, or direct-to-IP requests skip it.
- **Log `Content-Type`.** Default access logs don't record it, so multipart probing is invisible. `--waf-print` includes nginx `log_format` and Apache `LogFormat` snippets, and `--audit` uses them.
- **Know what you'll break:** file uploads, `FormData`/AJAX forms, Contact Form 7 (multipart even without files) and Livewire/Filament uploads stop working outside the allowlist.
- The narrow ModSecurity rule, which blocks only the `PHP_SESSION_UPLOAD_PROGRESS` field, is safe for almost every site. ModSecurity's multipart parser isn't PHP's, though, so treat it as a filter, not a guarantee.

To check from outside that your edge really rejects multipart, test against a PHP file, not `/`:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X PUT -F test=1 https://example.com/index.php   # want 403
```

## What does NOT help

These come up a lot, but they don't stop php2shell:

| Setting / measure | Why it doesn't help |
|---|---|
| `file_uploads = Off` | PHP still parses the multipart body and only skips the file parts |
| `enable_post_data_reading = Off` | Breaks every normal form, and doesn't cover the explicit `request_parse_body()` parsing in PHP 8.4 |
| `ini_set('session.upload_progress.enabled', 0)` | The setting is `PHP_INI_PERDIR`, and the body is parsed before your code runs |
| `disable_functions`, maintenance mode | The parsing happens before any of these apply |
| `post_max_size` alone | A multipart body without a usable length can get past the check, and per-part headers blow up memory inside the limit. Keep it low anyway, and enforce body size at the proxy |
| `RLIMIT_AS` / `RLIMIT_DATA` (`ulimit -v`) | **Makes it worse.** `mmap()` fails at the limit and takes the vulnerable `longjmp()` path |
| `error_reporting`, `@`, `display_errors = Off` | Don't stop the CVE-2026-109619 diagnostic consumer: the warning is raised even if nothing shows or logs it |
| Security plugins, framework middleware, CSRF checks | They run after PHP has already parsed the body |
| Blocking the `PHPSESSID` cookie | Breaks sessions, misses custom session names, and doesn't stop the parser |
| A firewall, HTTPS or new passwords | None of them tell you whether the interpreter is patched |

## Not covered (check these yourself)

- **`.user.ini` with PHP-CGI / LiteSpeed (non-FPM).** The setting is `PHP_INI_PERDIR`, so a site can turn it back on. `--audit` reports these files.
- **Docker images.** Configure them in the image instead, e.g. add `RUN echo 'session.upload_progress.enabled=Off' > /usr/local/etc/php/conf.d/zz-php2shell.ini` and rebuild. Restarting the same container doesn't pick up a new image. `--audit` lists running PHP containers.
- **Windows / IIS**, and software that bundles its own `php.exe` / `php-cgi.exe`. Not supported.
- **Old distros.** Ubuntu 20.04 has no PPA PHP builds, and no fix has been confirmed for it. Distro backports keep the upstream version number, so compare the package revision against your distro's security advisory (`--check` looks for the CVE ids in the package changelog).

## Interim measures php-fix does NOT apply (decide yourself)

The advisories list more measures. php-fix leaves them out because each one can take a server down or break apps:

| Measure | From | Why it isn't automatic |
|---|---|---|
| `memory_limit = -1`, set with `php_admin_value` | 109618 | Removes the predictable per-request limit the exploit relies on. Still incomplete. **It also removes the only per-request memory cap,** so one runaway script can eat the host's RAM. Use it only with per-worker cgroup limits (`memory.max`). A cgroup shared by the master and its workers takes them all down together |
| `pm.max_requests = 1` | 109619 | Stops worker reuse, so stale state doesn't reach the next request. Forks a process per request, which costs a lot of CPU |
| Lower `max_input_nesting_level`, `max_input_vars`, `max_file_uploads` and `post_max_size` | 109618 | Breaks large forms and multi-file uploads, depending on the app |
| Remove deprecated / invalid values from per-request INI overrides (`.htaccess` / Apache `php_value`, nginx `fastcgi_param PHP_VALUE`) | 109619 | Needs review of each site. `--audit` lists web server configs that pass `PHP_VALUE` |
| Stop attacker-reachable fatal errors and timeouts | 109619 | Application work |

## Rollback

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash -s -- --revert
```

This restores every file from the most recent run's backups, removes the mod_php and PHP 8.5 drop-ins and reloads services gracefully. Backup files are kept. Pass `--revert=20261021-120000` to restore a specific run, or add `--dry-run` to preview the revert first.

## After patching

Run `--check` to confirm every PHP binary, pool and container is on a fixed build. After that:

- **Upload progress:** the advisory recommends leaving it off if you don't need it. Turn it back on only if an app draws upload progress bars from `$_SESSION`.
- **PHP 8.5:** you can delete `zz-php2shell.ini` from `conf.d` once patched, or keep it.
- **Edge multipart rules:** remove them, or keep the narrow ModSecurity rule.
- Run `--audit`: patching doesn't remove a webshell that was planted before the update.

## Other tools and write-ups

| Resource | What it's for |
|---|---|
| [syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection) | Apache `.htaccess` multipart block with a test page that checks whether multipart still reaches PHP |
| [0xrsydn/php2shell-scan](https://github.com/0xrsydn/php2shell-scan) | Read-only **external** reachability check: does PHP still parse attacker multipart pre-auth? Supports before/after-patch baselines. Use it to verify your edge rules from outside |
| [mikensec/php2shell-lab](https://github.com/mikensec/php2shell-lab) | Offline lab for analysing a PoC sample and building detection rules (no exploit included) |
| [Florian Roth's process-watcher](https://github.com/Neo23x0/process-watcher) | Recommended by Huntress for watching PHP workers spawning shells when you have no EDR |
| [Censys query gist](https://gist.github.com/silascutler/c7f04537a79ace89569f979d964af0f9) | Finding exposed PHP hosts |
| [Vincent Schmalbach's write-up](https://www.vincentschmalbach.com/cve-2026-109618-and-cve-2026-109619-what-you-should-do-now/) | Container-tested rules for nginx, Apache, LiteSpeed, Caddy, FrankenPHP, HAProxy and Cloudflare, plus a list of what doesn't help |

Timeline note: the fix and advisories are public, so the patch diff now shows attackers where the bugs are. Expect mass exploitation. Patch first, then run `--audit`.

## References

- [PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 release announcement](https://www.php.net/)
- [GHSA-w8hw-w9fx-j79w / CVE-2026-109618: RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp / CVE-2026-109619: RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Help Net Security: PHP2Shell patched](https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/)
- [Tenable FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [PHP-UP-2026: pre-release write-up (heap UAF in session upload progress)](https://jackalsyn.com/posts/php-up-2026.html)
- [php2shell overview: SecureLayer7](https://blog.securelayer7.net/php-rce-cve-2026-109618-109619/)
- [Disabling session.upload_progress before the php2shell patch lands](https://lilting.ch/en/articles/php2shell-session-upload-progress-uaf)
- [Assessing and containing php2shell: DeXpose](https://www.dexpose.io/php2shell-php-rce-exposure-response/)
- [Apache-level multipart blocking toolkit: syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection)
- [Sansec: Critical PHP RCE](https://sansec.io/research/php2shell)
- [Huntress: Rapid Response, php2shell](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
- [Vincent Schmalbach: what you should do now](https://www.vincentschmalbach.com/cve-2026-109618-and-cve-2026-109619-what-you-should-do-now/)

## License

MIT. No warranty: test on staging first and keep the backups.
