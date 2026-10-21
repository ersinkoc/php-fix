# php-fix

One-line emergency mitigation for **php2shell** (**CVE-2026-109618** / **CVE-2026-109619**), the critical PHP RCE bugs (CVSS v4.0 9.2) announced for the out-of-band PHP release on **21 October 2026, 14:00 UTC**.

It sets `session.upload_progress.enabled = Off` across every PHP installation on a Linux server: distro packages, control panels, multiple PHP versions, PHP-FPM pools and Apache mod_php. Then it verifies the result through both the CLI and FPM binaries.

> [!IMPORTANT]
> **This is a stopgap, not a fix.** The PHP team's position is that *the only real mitigation is patching / upgrading PHP*.
> The public root-cause analysis puts the bug in `php_session_rfc1867_callback` (`ext/session/session.c`). That is a heap use-after-free: the upload-progress handler caches raw zval pointers into HashTables that get freed when the session is re-decoded mid-request. Disabling upload progress removes that path.
> However, reports say it **only closes one of the two suspected paths**. The multipart parser itself is still reachable by any `multipart/form-data` POST, and at least one researcher claims there is no working mitigation at all. Patch as soon as your distro or panel ships the fixed build.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash
```

### Verified install (recommended for production / fleets)

Pin to a release tag and check the SHA-256 checksum before anything runs as root:

```bash
curl -fsSLO https://raw.githubusercontent.com/ersinkoc/php-fix/v1.1.0/install.sh
echo "1f82cd74763a3dd8815e2cd574d8a9b98d522b0aafa7e94b380ddbf9e79848cf  install.sh" | sha256sum -c - && sudo bash install.sh
```

The checksum is also attached as `SHA256SUMS` to each [GitHub release](https://github.com/ersinkoc/php-fix/releases). Piping `main` into `sudo bash` means trusting whatever is on `main` at that moment.

### Options

```bash
curl -fsSL .../install.sh | sudo bash -s -- --dry-run      # show what would change, change nothing
curl -fsSL .../install.sh | sudo bash -s -- --no-restart   # don't reload PHP / web services
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Mitigation applied and verified (EOL warnings may still be printed) |
| `1` | Something failed or the setting is still On somewhere |
| `2` | A PHP **older than 5.4** was found. This mitigation **cannot** protect it |

## What it does

1. **Finds every `php.ini`** under the usual locations (`/etc`, `/usr/local/etc`, `/usr/local/lib`, `/usr/local/php*`, `/opt/cpanel`, `/opt/alt`, `/opt/plesk/php`, `/opt/remi`, `/etc/opt/remi`, `/www/server/php`, `/usr/local/lsws`), plus the one `php --ini` reports.
2. **Sets `session.upload_progress.enabled = Off`** in each one. It replaces an existing (commented or active) line, adds the setting under `[Session]`, or appends a `[Session]` block.
3. **Fixes overrides** in additional `.ini` files (`conf.d/*.ini`) that turn the setting back on.
4. **Hardens PHP-FPM pools.** Any `php_value` / `php_flag` for this directive becomes `php_admin_flag[session.upload_progress.enabled] = off`, so neither the app nor a `.user.ini` can re-enable it.
5. **Hardens Apache mod_php.** If mod_php is loaded, it drops in `zz-php2shell.conf` with `php_admin_flag session.upload_progress.enabled off`, which `.htaccess` cannot override. It runs `apachectl -t` first and rolls the file back if the config test fails.
   - Debian / Ubuntu: `/etc/apache2/conf-available/` + `a2enconf`
   - RHEL family: `/etc/httpd/conf.d/`
   - cPanel EA4: `/etc/apache2/conf.d/`
6. **Reloads services**: `php*-fpm`, `ea-php*`, `plesk-php*`, `apache2` / `httpd`, LiteSpeed, and restarts `lsphp` workers.
7. **Verifies** with every PHP **CLI** binary (`ini_get`) and every **php-fpm** binary (`php-fpm -i`). Each loads its own `php.ini`, so an FPM that still reads a different, unpatched ini is caught.
8. **Checks the PHP version** of every binary it finds:
   - **PHP < 5.4**: `session.upload_progress.enabled` doesn't exist there. Adding it does nothing, but the multipart parser is still exposed. The script reports *NOT PROTECTED* and exits `2`.
   - **PHP < 8.2 (EOL branches)**: these will most likely get no official patch. The script warns you to block or limit multipart POSTs at the proxy/WAF and plan an upgrade.

Every modified file is backed up next to the original as `<file>.bak-YYYYMMDD-HHMMSS`. The script refuses to write in directories that aren't root-owned or that are group/world-writable, to prevent symlink planting. It is idempotent: running it again skips everything that's already fixed.

### Tested

- Debian 13 (trixie) with PHP 8.4, `php-fpm` and `libapache2-mod-php`. The script fixed the php.ini files, a `conf.d` override and an FPM pool override, and passed `apachectl -t`. A second run changed nothing.
- **mod_php + `.htaccess` bypass:** with `php_flag session.upload_progress.enabled on` in `.htaccess`, a request returned `'1'` before the script ran and `'0'` after.
- The `< 5.4` (exit `2`) and EOL warning paths were tested with stub binaries. Symlink planting in world-writable directories is refused.

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

Requirements: bash 4+ (CentOS 7's bash 4.2 works), GNU coreutils / `sed` / `find` / `grep`, root.

## Side effects

Disabling upload progress only stops PHP from writing upload progress data into `$_SESSION`. **Normal file uploads keep working.** Only applications that poll `$_SESSION['upload_progress_*']` to draw upload progress bars lose that feature until you turn it back on.

## Manual verification

```bash
php -i | grep session.upload_progress.enabled          # CLI
php-fpm8.3 -i | grep session.upload_progress.enabled   # FPM's php.ini (adjust binary name)
```

For the real web SAPI, including FPM pool settings, put `<?php var_export(ini_get('session.upload_progress.enabled'));` in a temporary file and open it in a browser. `''` or `'0'` means Off. **Delete the file afterwards.**

## Not covered (check these yourself)

- **The second bug path (multipart parser).** For defense in depth until you patch, block or tightly limit `multipart/form-data` POSTs at your WAF / reverse proxy on endpoints that don't need uploads. With ModSecurity, a narrow rule for the upload-progress field:
  ```
  SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
    "id:1026109,phase:2,deny,status:403,log,msg:'php2shell upload_progress probe'"
  ```
  The field name comes from `session.upload_progress.name` (default `PHP_SESSION_UPLOAD_PROGRESS`). Adjust the rule if you changed it. For an Apache-level multipart block, see [syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection).
- **`.user.ini` with PHP-CGI / LiteSpeed (non-FPM).** `session.upload_progress.enabled` is `PHP_INI_PERDIR`, so a site can turn it back on. Search for it:
  ```bash
  grep -rEil 'session\.upload_progress\.enabled' /var/www /home --include=.htaccess --include=.user.ini 2>/dev/null
  ```
  `.user.ini` changes take up to `user_ini.cache_ttl` (default 300 s) to apply.
- **Docker images.** Configure them in the image instead, e.g. add `RUN echo 'session.upload_progress.enabled=Off' > /usr/local/etc/php/conf.d/zz-php2shell.ini` and rebuild.
- **Windows / IIS.** Not supported.

## Rollback

Each change has a timestamped backup. To restore one:

```bash
cp -p /etc/php/8.3/fpm/php.ini.bak-20261021-120000 /etc/php/8.3/fpm/php.ini
systemctl reload php8.3-fpm
```

To remove the mod_php drop-in, delete `zz-php2shell.conf` (Debian/Ubuntu: `a2disconf zz-php2shell`) and reload Apache.

List every backup this script created:

```bash
find / -xdev -name '*.bak-2026*' \( -name 'php.ini*' -o -name '*.ini.bak-*' -o -name '*.conf.bak-*' \) 2>/dev/null
```

## After patching

Once you're on the fixed PHP release, you can turn upload progress back on if your applications need it. If they don't, leaving it off reduces attack surface.

## Roadmap

These depend on the official fixed-version list (after 14:00 UTC):

- `--check`: per-binary report: patched / unpatched / EOL with no patch
- `--waf=print`: ready-to-paste ModSecurity / nginx / Apache snippets
- `--audit`: quick IoC sweep (recently changed `.php` in webroots, shells spawned by php-fpm / apache, multipart POST bursts in access logs, `upload_progress_` keys in session files)
- `--json`, `--revert`, plus CI with shellcheck and a distro test matrix

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
