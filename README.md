# php-fix

One-line emergency mitigation for **php2shell** (**CVE-2026-109618** / **CVE-2026-109619**), the critical PHP RCE bugs (CVSS v4.0 9.2) announced in October 2026.

It sets `session.upload_progress.enabled = Off` in every PHP installation on a Linux server: distro packages, control panels and multiple PHP versions side by side.

> [!IMPORTANT]
> **This is a stopgap, not a fix.** The PHP team's position is that *the only real mitigation is patching / upgrading PHP*. Public analysis suggests this setting closes the upload-progress use-after-free path, but it **may not cover both CVEs**, because the multipart parser itself can still be reached. Apply the official patched PHP release as soon as your distro or panel ships it.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash
```

Preview first without changing anything:

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash -s -- --dry-run
```

Apply without reloading services (you reload them yourself later):

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash -s -- --no-restart
```

If you'd rather read it before running it (recommended):

```bash
curl -fsSLO https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh
less install.sh
sudo bash install.sh
```

## What it does

1. **Finds every `php.ini`** under the usual locations (`/etc`, `/usr/local/etc`, `/usr/local/lib`, `/usr/local/php*`, `/opt/cpanel`, `/opt/alt`, `/opt/plesk/php`, `/opt/remi`, `/etc/opt/remi`, `/www/server/php`, `/usr/local/lsws`), plus the one `php --ini` reports.
2. **Sets `session.upload_progress.enabled = Off`** in each one. It replaces an existing (commented or active) line, adds the setting under `[Session]`, or appends a `[Session]` block.
3. **Fixes overrides** in additional `.ini` files (`conf.d/*.ini`) that turn the setting back on.
4. **Hardens PHP-FPM pools.** Any `php_value` / `php_flag` / `php_admin_*` for this directive becomes `php_admin_flag[session.upload_progress.enabled] = off`, so applications can't re-enable it.
5. **Reloads services**: `php*-fpm`, `ea-php*`, `plesk-php*`, `apache2` / `httpd`, LiteSpeed, and restarts `lsphp` workers.
6. **Verifies** the result with every PHP CLI binary it can find and prints a summary.

Every modified file is backed up next to the original as `<file>.bak-YYYYMMDD-HHMMSS`. Running the script again is safe: files that are already fixed are skipped.

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

Requirements: bash 4+, GNU `sed`, `find`, `grep`, root.

## Side effects

Disabling upload progress only stops PHP from writing upload progress data into `$_SESSION`. **Normal file uploads keep working.** Only applications that poll `$_SESSION['upload_progress_*']` to draw upload progress bars lose that feature until you turn it back on.

## Manual verification

```bash
php -i | grep session.upload_progress.enabled
# session.upload_progress.enabled => Off => Off
```

For FPM / web SAPIs, put `<?php echo ini_get('session.upload_progress.enabled') === '' || ini_get('session.upload_progress.enabled') === '0' ? 'OFF' : 'ON';` in a temporary file, open it in a browser, then **delete it**.

## Not covered (check these yourself)

- **`.user.ini` / `.htaccess` in web roots.** `session.upload_progress.enabled` is `PHP_INI_PERDIR`, so a site can turn it back on with `php_flag session.upload_progress.enabled on` (mod_php) or a `.user.ini`. FPM pools hardened with `php_admin_flag` block this. To search:
  ```bash
  grep -rEil 'session\.upload_progress\.enabled' /var/www /home --include=.htaccess --include=.user.ini 2>/dev/null
  ```
  `.user.ini` changes take up to `user_ini.cache_ttl` (default 300 s) to apply.
- **Docker images.** Configure them in the image instead, e.g. add `RUN echo 'session.upload_progress.enabled=Off' > /usr/local/etc/php/conf.d/zz-php2shell.ini` and rebuild.
- **Windows / IIS.** Not supported.
- **The second bug path.** For defense in depth until you patch, consider blocking or tightly limiting `multipart/form-data` POSTs at your WAF / reverse proxy on endpoints that don't need uploads.

## Rollback

Each change has a timestamped backup. To restore one:

```bash
cp -p /etc/php/8.3/fpm/php.ini.bak-20261021-120000 /etc/php/8.3/fpm/php.ini
systemctl reload php8.3-fpm
```

List every backup this script created:

```bash
find / -xdev -name '*.bak-2026*' \( -name 'php.ini*' -o -name '*.ini.bak-*' -o -name '*.conf.bak-*' \) 2>/dev/null
```

## After patching

Once you're on the fixed PHP release, you can turn upload progress back on if your applications need it. If they don't, leaving it off reduces attack surface.

## References

- [PHP security announcements](https://www.php.net/)
- [php2shell overview: SecureLayer7](https://blog.securelayer7.net/php-rce-cve-2026-109618-109619/)
- [Disabling session.upload_progress before the php2shell patch lands](https://lilting.ch/en/articles/php2shell-session-upload-progress-uaf)
- [Assessing and containing php2shell: DeXpose](https://www.dexpose.io/php2shell-php-rce-exposure-response/)
- [Apache-level multipart blocking toolkit: syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection)

## License

MIT. No warranty: test on staging first and keep the backups.
