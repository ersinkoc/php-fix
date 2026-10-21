# php-fix

[![CI](https://github.com/ersinkoc/php-fix/actions/workflows/ci.yml/badge.svg)](https://github.com/ersinkoc/php-fix/actions/workflows/ci.yml)

One-line emergency mitigation for **php2shell** (**CVE-2026-109618** / **CVE-2026-109619**), the critical PHP RCE bugs (CVSS v4.0 9.2) announced for the out-of-band PHP release on **21 October 2026, 14:00 UTC**.

It sets `session.upload_progress.enabled = Off` across every PHP installation on a Linux server: distro packages, control panels, multiple PHP versions, PHP-FPM pools and Apache mod_php. Then it verifies the result through both the CLI and FPM binaries. Read-only modes check patch status (`--check`), sweep for signs of compromise (`--audit`) and print WAF rules for the second attack path (`--waf-print`).

> [!IMPORTANT]
> **This is a stopgap, not a fix.** The PHP team's position is that *the only real mitigation is patching / upgrading PHP*.
> The public root-cause analysis puts the bug in `php_session_rfc1867_callback` (`ext/session/session.c`). That is a heap use-after-free: the upload-progress handler caches raw zval pointers into HashTables that get freed when the session is re-decoded mid-request. Disabling upload progress removes that path.
> However, reports say it **only closes one of the two suspected paths**. The multipart parser itself is still reachable by any `multipart/form-data` POST, and at least one researcher claims there is no working mitigation at all. Patch as soon as your distro or panel ships the fixed build.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash
```

### Verified install (recommended for production / fleets)

Piping `main` into `sudo bash` means trusting whatever is on `main` at that moment. For production, use a release instead. Every release is built by GitHub Actions and ships with a `SHA256SUMS` file and a signed [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations):

```bash
V=v1.2.2
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
| `... --check` | No | Per binary: **PATCHED** / **UNPATCHED** / **EOL, no patch** / unknown. Also detects distro backports via the package changelog |
| `... --audit[=HOURS]` | No | Heuristic indicator-of-compromise sweep (default: last 48 h). Runs at lowest CPU/IO priority |
| `... --waf-print` | No | Prints ModSecurity / nginx / Apache / Cloudflare rules for the multipart path |
| `... --revert[=STAMP]` | **Yes** | Restores the backups of the last run (or of the run `STAMP`, e.g. `20261021-120000`) and removes the mod_php drop-in |

With curl, pass options like this: `curl -fsSL .../install.sh | sudo bash -s -- --check`

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. `--check`: everything patched. `--audit`: nothing flagged |
| `1` | A step failed, or the setting is still On somewhere. `--check`: something is unpatched or its status is unknown |
| `2` | A PHP **older than 5.4** was found. This mitigation **cannot** protect it |
| `3` | `--audit` found items to review |

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
4. **Hardens PHP-FPM pools.** Any `php_value` / `php_flag` for this directive becomes `php_admin_flag[session.upload_progress.enabled] = off`, so neither the app nor a `.user.ini` can re-enable it.
5. **Hardens Apache mod_php.** If mod_php is loaded, it drops in `zz-php2shell.conf` with `php_admin_flag session.upload_progress.enabled off`, which `.htaccess` cannot override.
   - Debian / Ubuntu: `/etc/apache2/conf-available/` + `a2enconf`
   - RHEL family: `/etc/httpd/conf.d/`
   - cPanel EA4: `/etc/apache2/conf.d/`
6. **Reloads services gracefully**: `php*-fpm`, `ea-php*`, `plesk-php*`, `apache2` / `httpd`, LiteSpeed.
7. **Verifies** with every PHP **CLI** binary (`ini_get`) and every **php-fpm** binary (`php-fpm -i`). Each loads its own `php.ini`, so an FPM that still reads a different, unpatched ini is caught.
8. **Checks the PHP version** of every binary it finds:
   - **PHP < 5.4**: the setting doesn't exist there, but the multipart parser is still exposed. The script reports *NOT PROTECTED* and exits `2`.
   - **PHP < 8.2 (EOL branches)**: these will most likely get no official patch. The script warns you to block or limit multipart POSTs at the proxy/WAF (`--waf-print`) and plan an upgrade.

## `--audit`: what it looks at

This is a heuristic sweep, not proof either way. Every finding needs a human to look at it.

- PHP / `.htaccess` / `.user.ini` files changed in web roots within the window (listed for review; CMS updates are normal noise)
- Webshell-like code in those files (`eval(base64_decode(...))`, `system($_POST...)`, and similar)
- `.htaccess` / `.user.ini` files that turn upload progress back on
- Shells or interpreters (`sh`, `bash`, `nc`, `python`, `perl`, `curl`, `wget`, …) whose parent is PHP or the web server. Some are legitimate, e.g. `mail()` calling `sh -c sendmail`.
- Session files containing `upload_progress_` data, meaning the vulnerable code path was exercised
- Recently changed cron jobs
- Busiest POST-to-`.php` clients in the current access logs (context only)
- Running PHP Docker containers, which this script cannot reach

## Tested

CI runs [`tests/run.sh`](tests/run.sh) on every push. It installs real PHP from the distro packages and exercises every mode end to end:

| Distro | PHP | Notes |
|---|---|---|
| Debian 13 (trixie) | 8.4 | php-fpm + Apache mod_php |
| Debian 12 (bookworm) | 8.2 | php-fpm + Apache mod_php |
| Ubuntu 24.04 | 8.3 | php-fpm + Apache mod_php |
| AlmaLinux 9 | 8.0 (EOL) | php-fpm + httpd |

The tests cover:
- dry-run changes nothing; php.ini, `conf.d` and FPM pool overrides are fixed; a second run is idempotent
- **`.htaccess` with `php_flag … on` cannot re-enable the setting under mod_php** (a real HTTP request returns `'0'`)
- `--check`, and `--audit` catching a planted webshell
- `--audit` output stays clean when a malicious file name carries terminal escape sequences
- the `--waf-print` Apache rule, pasted into a vhost, passes `apachectl -t` and behaves as intended:
  - a multipart POST to `/t.php` gets `403`
  - the prefix trick `/wp-admin/async-upload.php-evil.php` is blocked
  - the allowlisted path and normal POSTs pass
- the EOL warning and the `< 5.4` exit `2` path
- `--revert` restores php.ini byte-for-byte and leaves Apache valid
- world-writable directories are refused

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

## Not covered (check these yourself)

- **The second bug path (multipart parser).** For defense in depth until you patch, run `--waf-print` and apply the rules that fit your setup. The narrow ModSecurity rule (blocks only the upload-progress field) is safe for almost every site. The broad "multipart only on allowlisted paths" rules need your real upload URLs first. List **exact script paths** anchored with `^…$`, never prefixes like `^/upload` (that also matches `/upload-anything.php`). The Apache rule goes inside each `<VirtualHost>`. Also see [syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection).
- **`.user.ini` with PHP-CGI / LiteSpeed (non-FPM).** The setting is `PHP_INI_PERDIR`, so a site can turn it back on. `--audit` reports these files.
- **Docker images.** Configure them in the image instead, e.g. add `RUN echo 'session.upload_progress.enabled=Off' > /usr/local/etc/php/conf.d/zz-php2shell.ini` and rebuild. `--audit` lists running PHP containers.
- **Windows / IIS.** Not supported.

## Rollback

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash -s -- --revert
```

This restores every file from the most recent run's backups, removes the mod_php drop-in and reloads services gracefully. Backup files are kept. Pass `--revert=20261021-120000` to restore a specific run, or add `--dry-run` to preview the revert first.

## After patching

Run `--check` to confirm every PHP binary is on a fixed build. Once you're on the fixed PHP release, you can turn upload progress back on if your applications need it. If they don't, leaving it off reduces attack surface.

## Roadmap

- Fill in the official fixed versions for `--check` as soon as the advisory is out
- `--json` output for fleet tooling (Ansible / Salt)

## References

- [PHP-UP-2026: primary technical write-up (heap UAF in session upload progress)](https://jackalsyn.com/posts/php-up-2026.html)
- [php-src GitHub security advisories](https://github.com/php/php-src/security/advisories)
- [PHP news / release announcements](https://www.php.net/)
- [php2shell overview: SecureLayer7](https://blog.securelayer7.net/php-rce-cve-2026-109618-109619/)
- [Disabling session.upload_progress before the php2shell patch lands](https://lilting.ch/en/articles/php2shell-session-upload-progress-uaf)
- [Assessing and containing php2shell: DeXpose](https://www.dexpose.io/php2shell-php-rce-exposure-response/)
- [Apache-level multipart blocking toolkit: syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection)

## License

MIT. No warranty: test on staging first and keep the backups.
