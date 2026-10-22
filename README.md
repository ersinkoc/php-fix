# php-fix

[![CI](https://github.com/ersinkoc/php-fix/actions/workflows/ci.yml/badge.svg)](https://github.com/ersinkoc/php-fix/actions/workflows/ci.yml)

One-line emergency mitigation for **php2shell** (**CVE-2026-109618** / **CVE-2026-109619**), two critical unauthenticated PHP RCE bugs (CVSS v4.0 9.2), for servers that can't be patched right away.

> [!IMPORTANT]
> **The fix is out. Update PHP first:** **8.5.12, 8.4.27, 8.3.36 and 8.2.35** (released 21 October 2026). Distro builds may keep the old upstream number with the fix backported, so check your distro's tracker. PHP 8.1 and older get no php.net fix.
> The PHP team says updating is the only complete mitigation. This script is for the time until you can.

> [!WARNING]
> **Attacks started before disclosure.** Amazon's MadPot honeypots saw the first exploitation attempt on **17 October 2026**, four days before the patch. More followed on 21 October, seen by Amazon, Cloudflare, watchTowr and VulnCheck. One attempt planted a webshell into a session file through `PHP_SESSION_UPLOAD_PROGRESS`. VulnCheck reports a weaponized CVE-2026-109618 exploit working against PHP 8.4.26 on x86-64 **with ASLR on and `display_errors=Off`**. On ARM64 only the memory leak works so far. Cloudflare counted thousands of attempts in the 10 hours before the announcement and hundreds of thousands within 2 hours after; on 22 October its CEO put the total in the millions. Amazon calls it "broadly exploited in the wild". No successful compromise has been confirmed publicly yet. CISA's KEV catalog still didn't list the CVEs on 22 October (catalog 2026.10.21).
>
> **Don't run public "PoCs".** watchTowr says none of the mass-sprayed ones achieve RCE: they fail, measure timing or crash the target. Sansec adds that the public ones don't work against a default PHP install and mostly need a local file inclusion bug in the app. That is no reason to wait: Calif's own chain worked against stock Magento, WordPress, Drupal, Joomla, Nextcloud, Laravel and Symfony. JFrog and AhnLab found fake repositories, including one that runs a hidden encoded payload, and fake exploits aimed at security researchers have shipped malware before. CERT-EU (SA 2026-018) and the UK NCSC advise taking internet-facing PHP offline if you can't patch now.
>
> **Investigate from 17 October, not from the disclosure date:** `--audit=exposure` covers that whole window. See [Published indicators](#published-indicators-iocs).

It sets `session.upload_progress.enabled = Off` across every PHP installation on a Linux server: distro packages, control panels, multiple PHP versions, PHP-FPM pools and Apache mod_php. On **unpatched PHP 8.5** it also sets `fatal_error_backtraces = Off`. Then it verifies the result through the CLI and FPM binaries and every running FPM pool. Read-only modes check patch status against the fixed versions (`--check`), sweep for signs of compromise (`--audit`) and print WAF rules for the multipart path (`--waf-print`).

## What the two bugs are (from the official advisories)

| | [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w): RCE via OOM corruption | [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp): RCE via stale global state |
|---|---|---|
| Bug | PHP leaves the request with `longjmp()` on out-of-memory while request memory is only partly initialized. Shutdown then trusts it. | Global state survives the request that owned it. A later request on the same worker reads it before startup resets it. |
| How it's reached | Mainly **multipart parsing**: bodies without a usable length, unlimited headers per part, empty file fields and nested names exhaust `memory_limit` while staying under `post_max_size` | **Producer:** a fatal error or OOM (on 8.5, `fatal_error_backtraces`). **Consumer:** session upload progress, or a warning from a per-request INI override |
| Confirmed against | Apache mod_php (full RCE). FPM, FrankenPHP and LSAPI are likely affected | mod_php, plus FPM via the upload-progress path |
| What php-fix does | Nothing in PHP config can close it. Block multipart at the edge (`--waf-print`) | `session.upload_progress.enabled = Off`, plus `fatal_error_backtraces = Off` on PHP 8.5 |

Neither setting is complete. They close the confirmed paths, not every variant. **Patch.**

Imperva reproduced five exploitation techniques on top of these bugs:
- three session use-after-frees, one of which leaks about 67 KB of worker memory in the `Set-Cookie: PHPSESSID` header
- an OPcache stale class-cache pointer that turns into an **arbitrary file read**
- a `fatal_error_backtraces` use-after-free

Turning upload progress off removes the trigger for three of the five. For the OPcache path, Imperva lists `opcache.enable = 0` as a temporary measure. PHP's advisories don't mention it, and it costs a lot of CPU. `--interim` shows whether OPcache is on in each pool.

Red Hat rates the bugs *Important* rather than *Critical* for standard RHEL, because RHEL uses PHP-FPM, not mod_php: FPM workers exit on an early startup failure before they reach the corrupted state. That makes RCE harder on FPM, not impossible. The upload-progress path is confirmed against FPM too.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash
```

### Verified install (recommended for production / fleets)

Piping `main` into `sudo bash` means trusting whatever is on `main` at that moment. For production, use a release instead. Every release is built by GitHub Actions and ships with a `SHA256SUMS` file and a signed [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations):

```bash
V=v1.16.0
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
| `... --check` | No | **PATCHED** / **UNPATCHED** / **EOL, no patch** / unknown against 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 for every PHP binary, **every running FPM pool (live)** and **every running Docker container** (`docker exec php`). Also detects distro backports via the package changelog, and warns about held / version-locked PHP packages (`apt-mark hold`, `dnf versionlock`) that would silently skip the update. **After updating:** flags workers still running the old (replaced) PHP, and prints the update + restart commands for each PHP source it finds (Plesk, cPanel, DirectAdmin, CloudLinux, Remi, sury / ondrej, LiteSpeed, Docker) |
| `... --audit[=HOURS]` | No | Heuristic indicator-of-compromise sweep (default: last 48 h). Runs at lowest CPU/IO priority. **`--audit=exposure`** covers everything since the first attacks on 17 Oct 2026 |
| `... --interim` | No | Which [interim measures](#interim-measures-php-fix-does-not-apply-decide-yourself) are in effect, per FPM binary and **per running pool** (`memory_limit`, `post_max_size`, input limits, `file_uploads`, `display_errors`, `pm.max_requests`, cgroup memory cap, nginx / Apache body caps). Flags settings that make the OOM bug **easier** to reach: `RLIMIT_AS` / `RLIMIT_DATA` on PHP / web server processes, systemd `LimitAS=` / `LimitDATA=`, `ulimit -v` / `-d`, Apache `RLimitMEM` (exit 1) |
| `... --waf-print` | No | Prints rules for the multipart path: ModSecurity, nginx, Apache, LiteSpeed/.htaccess, Caddy/FrankenPHP, HAProxy, Cloudflare, AWS WAF |
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

This is a heuristic sweep, not proof either way. Every finding needs a human to look at it. Run **`--audit=exposure`** once: exploitation began on 17 October, and the default 48 h window no longer reaches back that far. Datadog reports that a successful exploit can return a normal **HTTP 200** and leave the worker running, so a clean access log doesn't rule out compromise.

- PHP / `.htaccess` / `.user.ini` files changed in web roots within the window (listed for review; CMS updates are normal noise)
- Webshell-like code in those files (`eval(base64_decode(...))`, `system($_POST...)`, and similar)
- **Disguised webshells** written in the window (Elastic): double extensions (`avatar.php.jpg`, `x.phtml.png`) and images that carry PHP code (polyglots: `GIF89a<?php …`)
- `.htaccess` / `.user.ini` files that turn upload progress back on
- Shells or interpreters (`sh`, `bash`, `nc`, `python`, `perl`, `curl`, `wget`, …) whose parent is PHP or the web server. Some are legitimate, e.g. `mail()` calling `sh -c sendmail`.
- Session files containing `upload_progress_` data, meaning the vulnerable code path was exercised
- **Session files holding PHP code** (`<?php`, `PWNED::`, `system(`…). One attack seen in the wild planted a webshell into a session file through `PHP_SESSION_UPLOAD_PROGRESS`, then tried to include it via `php://filter`
- Recently changed cron jobs
- **Published indicators in current *and rotated* access logs** of the window (`.1`, `.gz`, `-YYYYMMDD`):
  - requests from the IP addresses Amazon and VulnCheck published (shared infrastructure, so investigate, don't conclude)
  - `php://filter` in URLs (read-back of a planted session file)
  - `PHP_SESSION_UPLOAD_PROGRESS` in URLs
  - the scanner user agents `php2shell-scan` / `php2shell-verify` / `php2shell-poc` and `/php2shell-probe-*` requests (reported as context; your own checks show up here too)
- Changed `/etc/passwd`, `/etc/shadow`, `/etc/group`, sudoers and SSH `authorized_keys` (root, `/home/*`, `/var/www`), and web server users (`www-data`, `apache`, `nginx`, …) that have a login shell
- Busiest POST-to-`.php` clients in the current access logs (context only)
- If your access logs record `Content-Type` (see the logging snippets in `--waf-print`): the top multipart senders, and every **multipart request answered with 500–504**. A worker crashing under multipart is the strongest exploitation signal you can get from logs.
- **PHP / web worker crashes** (`SIGSEGV`, `exited on signal 11`, kernel `segfault at … php-fpm`) in FPM and Apache logs and the kernel log. Memory-corruption exploits usually crash workers while they are being tuned.
- **Request-startup out-of-memory errors**: `Allowed memory size of … bytes exhausted … in Unknown on line 0` in FPM, PHP, nginx and Apache error logs. "Unknown on line 0" means memory ran out while PHP was parsing the request, before any script ran. That is the CVE-2026-109618 trigger ([Datadog](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)). Ordinary OOMs inside scripts are not counted.
- PHP files dropped in `/tmp`, `/var/tmp` or `/dev/shm`
- Reverse-shell command lines on any process (`/dev/tcp/`, `mkfifo … nc`, `nc -e`, `bash -i`, `socat … exec`, `fsockopen`, `pty.spawn`)
- Shells or interpreters running as a web user (`www-data`, `apache`, `nginx`, `nobody`, …) and detached from their parent (double-forked)
- **Fileless execution**: any process whose binary is a `memfd` (run straight from memory), and web-user processes whose binary outside `/usr` / `/opt` was deleted after start (dropper ran, then removed itself). Inside a container without `CAP_SYS_PTRACE` root can't see other users' binaries, so run `--audit` on the host
- `Failed to decode session object` in PHP / FPM logs: corrupted or planted session data. Context only; it matters next to worker crashes
- Shells or interpreters holding network connections (`ss`)
- Running PHP Docker containers, which this script cannot reach

If `ps` or `ss` is missing (e.g. minimal container images), the audit says which checks it skipped.

## Published indicators (IOCs)

From [Amazon Threat Intelligence](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/) and [VulnCheck](https://www.vulncheck.com/blog/php2shell-vulnerabilities) (21 October 2026). `--audit` searches access logs for them. The addresses belong to anonymization and hosting networks that other people use too, and they rotate within days. **Investigate hits; don't treat them as proof, and don't rely on blocking them.**

| Indicator | Meaning |
|---|---|
| `103.216.220.92` | First attempt, **17 Oct**, before disclosure (Amazon MadPot) |
| `31.223.184.166`, `37.19.200.5`, `134.209.159.64`, `103.114.163.188`, `95.217.98.37` | Attempts on 21 Oct (Amazon) |
| `85.11.167.243`, `45.198.224.169`, `109.71.252.97`, `91.90.123.25` | Multipart probing of `/index.php` and `/`, 21 Oct (VulnCheck) |
| `221.14.159.134` | Exploitation attempt, 21 Oct 17:22 UTC: webshell planted into a session file, then read back. A residential ISP address, so follow it up first (VulnCheck) |
| `PHP_SESSION_UPLOAD_PROGRESS` field in a multipart body | The upload-progress path. Needs body logging or a WAF to see it |
| `GET /download.php?file=php://filter/...` | Attempt to include the planted session file |
| Session file `sess_xqsuvwz3n97wu8j3emz1axuo5y`, boundary `------p2s9rdme2st6guc9g0rafic`, file name `p2s.txt` | That attempt's artifacts |
| `<?php echo 'PWNED::'; system($_GET['c']); ?>`, `PWNED::` in a response | The planted payload; `PWNED::` in a response means code ran |
| User agents `php2shell-scan/109618`, `php2shell-scan/1.3 (...)`, `php2shell-verify/1.0`, `Mozilla/5.0 (php2shell-poc)` | Scanners. Some are defenders checking their own hosts |
| `/php2shell-probe-<random>.php` / `.txt`, `/vuln.php`, `/phpinfo.php`, `/info.php`, `/i.php` | Probe paths |
| Multipart part `a`, SHA-256 `150ae88f0999032e2a6113501d6082f54a3ed98d02427b21a96e773a27d7bf16` or `40caf199ca1ebe056a74427f8e9db06c66899e33ae09c0ec2769ec70bf6dd8e7`; part `b`, `27d926a6708d6769d97d065e7a5a860ab496eab272c03d1cebc55ec71b954fa2` | Scanner upload bodies |

Hunting on the host goes beyond these: PHP workers starting shells or downloaders, `whoami` / `id` run as the web user, new PHP files in upload / cache / temp directories, new cron jobs, accounts and SSH keys. `--audit` covers all of them. **Before you restart or clean anything, save the logs, configs and suspicious files** (watchTowr, NCSC): a restart wipes what's only in memory, and log rotation deletes the oldest days.

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
- **`--waf-print`:** the AWS WAF rule is valid JSON
- **`--waf-print` rules, run in real Apache and nginx** (configtest passes in both, including the logging snippets):
  - multipart POST, multipart **PUT** and a mixed-case `Content-Type` get `403`, as does the prefix trick `/wp-admin/async-upload.php-evil.php`
  - the allowlisted path, urlencoded POSTs and JSON POSTs pass
  - on Apache: a subfolder `.htaccess` with `RewriteEngine On` + `Require all granted` cannot bypass the rule, and neither can a vhost with its own rewrite rules
- **Live pool verification:**
  - `--check` and the fix itself read the live value from running FPM pools over FastCGI, over a unix socket and over TCP, including a quoted `listen = ".../$pool.sock"` path (php-fpm expands `$pool`)
  - a pool added later with `php_admin_value[…] = 1` is reported as mitigation off
  - `--check --json` produces valid JSON
- **`--probe`:** reports `0` (blocked) against Apache with the rule, and `1` (reaches PHP) without it
- **`--user-ini`:** writes `.user.ini` as the site user, is idempotent, and is refused as root
- **PHP 8.5 (stub binary):** `--check` flags `fatal_error_backtraces` On; the fix writes the `conf.d` drop-in only on unpatched 8.5, verifies it, is idempotent, and `--revert` removes it
- **Fixed versions:** `--check` classifies real distro PHP as PATCHED / UNPATCHED / EOL (Debian trixie ships 8.4.27; Ubuntu 24.04's backported 8.3.6 is detected from its changelog)
- **`--interim`:** reads the interim settings from live FPM pools (including `opcache.enable`), flags a PHP process started with `RLIMIT_AS` (`prlimit --as`) and an Apache `RLimitMEM`, and exits 0 on a clean host
- **cPanel EA4:** an ea-php74 package at release 19 is PATCHED, and an older release says `upgrade 'ea-php*'` (Debian / Ubuntu images, with a stub .deb)
- **DirectAdmin:** a 7.4 binary built after CustomBuild's CVE patch is PATCHED, and an older one says `da build php`. Imunify360 rulesets older than 8.83 are flagged, 8.83–8.84 asked to update, 8.85 accepted
- **Ubuntu:** `--check` recognizes 24.04's `8.3.6-0ubuntu0.24.04.13` as fixed from the USN table, and reports a build older than the table entry as unpatched
- **After an update:** `--check` reports FPM workers still running a replaced binary, prints update and restart hints, and stops reporting once FPM is restarted. It warns about `memory_limit = -1` left on a patched FPM, but not on CLI, where `-1` is the default
- **`--audit` and `--check`:**
  - `--audit` flags a web-user process running a deleted binary and reports `Failed to decode session object` lines. The PHPSESSID disclosure rule from `--waf-print` is checked against real IDs (32 hex, 26-char base32, `deleted`) and against URL-encoded and overlong leaks
  - `--audit` flags a planted webshell, a worker `SIGSEGV` log line, a request-startup OOM (`in Unknown on line 0`, while an ordinary in-script OOM is ignored), a PHP file in `/tmp`, a reverse-shell command line, and a multipart request answered with `502` in a `Content-Type`-logging access log
  - `--audit` flags an image polyglot (`GIF89a<?php`) and an `avatar.php.jpg`, and leaves a clean image alone
  - `--audit` finds a published IOC address and a `php://filter` read-back in a **rotated, gzipped** access log, reports a `php2shell-scan` user agent, and flags a session file carrying a `PWNED::` webshell. `--audit=exposure` computes the window back to 17 Oct
  - `--audit` output stays clean when file names carry terminal escapes (ESC, 8-bit and UTF-8 C1)
  - `--check` runs; the EOL warning and the `< 5.4` exit `2` path are tested with stub binaries

Run the tests locally with: `docker run --rm --cap-add SYS_PTRACE -v "$PWD:/src:ro" debian:trixie bash /src/tests/run.sh`

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

Control panels and several repositories ship **their own PHP builds**. `apt upgrade` / `dnf upgrade` doesn't touch Plesk's, cPanel's, DirectAdmin's or CloudLinux's PHP. One server can have several of these side by side. `--check` lists every PHP it finds, detects where each one comes from, and prints the update command for that source.

### Where the fixed builds are (as of 22 October 2026)

This changes hour by hour. Check the vendor's page, then confirm with `--check`.

| Source | Where it lives | Status | Update |
|---|---|---|---|
| **php.net** upstream | — | ✅ 8.2.35, 8.3.36, 8.4.27, 8.5.12. Minimal source backports for 7.4, 8.0 and 8.1 are published for vendors | — |
| **Plesk** (Linux) | `/opt/plesk/php/X.Y` | ✅ all four branches. Windows: in progress | Tools & Settings → Updates, or `plesk installer update` |
| **cPanel EA4** | `/opt/cpanel/ea-phpXY` | ✅ [EA4 25.91](https://docs.cpanel.net/changelogs/easyapache-4-change-log-25/): ea-php82–85 → 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. **ea-php74 / 80 / 81 backported at the same version**: `7.4.33-19`, `8.0.30-12`, `8.1.34-5` | `dnf upgrade 'ea-php*'` (`yum` on EL7, `apt` on Ubuntu), or `/scripts/upcp`. Then `/scripts/restartsrv_apache_php_fpm` |
| **DirectAdmin CustomBuild** | `/usr/local/phpXY` (compiled) | ✅ new DA build on `current` and `stable`: 8.2–8.5 bumped, **7.4 / 8.0 / 8.1 patched at the same version number** (shown with `*`). ⏳ 7.3–5.6 later. 8.1 may fail to build on some systems | `da update && da build php`. PHP is not rebuilt automatically unless the CustomBuild cron is enabled |
| **CloudLinux ea-php** (cPanel on CloudLinux) | `/opt/cpanel/ea-phpXY` | ✅ ea-php52–85 in stable since 21 Oct 20:55 UTC, with CloudLinux's own numbering, e.g. ea-php74 `7.4.33-18.elX.cloudlinux.13`, ea-php82 `8.2.34-2.elX.cloudlinux.1`. The upstream number stays old; `--check` goes by the changelog | `yum update 'ea-php*'`. Verify: `rpm -q --changelog ea-php74-php-cli \| grep -E 'CVE-2026-(109618\|109619)'` |
| **CloudLinux alt-php** | `/opt/alt/phpXY` | ✅ **CloudLinux 7 / 8 / 9: alt-php 5.2–8.5 in stable since 22 Oct 00:07 UTC.** CloudLinux 10: alt-php52 in stable, the others from the TuxCare ELS ALT PHP repository. Ubuntu 22.04 alt-php: stable since 21 Oct 21:48 UTC ([status](https://cloudlinux.statuspage.io/)) | `yum clean all && yum update 'alt-php*'` |
| **CloudLinux** native `php` | `/etc/php.ini` | 🔄 rolling out (22 Oct 05:23 UTC): ✅ CL9 PHP 8.2 / 8.3, CL8 PHP 8.2. 🔄 CL10 8.3, CL9 8.0 / 8.1, CL8 7.2 / 7.4 / 8.0, CL7 5.4. ⏳ CL8 7.3 | `yum update 'php*'` |
| **TuxCare ELS / ESU** | vendor repos | ✅ RHEL 7, Oracle Linux 6 / 7, CentOS 8.4 / 8.5 / Stream 8, Amazon Linux 2, AlmaLinux 9.2 / 9.8 ESU, Ubuntu 16.04–20.04 ELS, Alpine 3.18 ELS. ⏳ CloudLinux 7, Debian 10 / 11 ELS, CentOS 6 / 7, PHP for Windows | vendor update command |
| **Imunify360** WAF (cPanel, Plesk, CloudLinux) | ModSecurity vendor rules | ✅ ruleset **8.83** blocks the public exploit shape on Apache; **8.84 / 8.85 also block on LiteSpeed**. Scanning IPs get a CAPTCHA. Interim only | `imunify360-agent update --force modsec-rules`. `--check` reports the installed ruleset version |
| **Cloudflare** WAF | edge | ✅ temporary rules for the known exploit vectors, for all plans including Free. Only covers traffic that goes through Cloudflare; the CTO calls it "a STOPGAP only" | nothing to do; lock the origin to Cloudflare IPs, or the rules can be bypassed |
| **Check Point** IPS / WAF | gateway | ✅ IPS protection CPAI-2026-15172 | set new critical protections to Prevent. TLS traffic must be inspected |
| **packages.sury.org** (Debian 12/13, Ubuntu 22.04/24.04) | `/etc/php/X.Y` | ✅ 8.2–8.5 on amd64. ⏳ **arm64 mostly still on the old builds.** Package index read late on 22 Oct: bookworm arm64 has **8.5.12** but still 8.2.34 / 8.3.35 / 8.4.26; trixie arm64 still 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11. The maintainer says arm builds run under qemu and have "a much longer tail". On arm64 hosts `--check` prints what apt offers for each installed branch | `apt-get install --only-upgrade 'php8.3*'`. On arm64, check `apt-cache policy php8.3` |
| **ppa:ondrej/php** (Launchpad) | `/etc/php/X.Y` | ✅ 8.2–8.5 on amd64 and arm64 (arm64 8.5 since 21:22 UTC) | `apt upgrade`. Ubuntu on arm64: this is the fixed source while sury's arm64 lags |
| **Ubuntu** own packages | `/etc/php/X.Y` | ✅ every release, including ESM ([USN-8948-1 / -2](https://ubuntu.com/blog/php2shell-vulnerability-fixes-available)). See [Ubuntu](#ubuntu) below | `apt upgrade` |
| **Debian** own packages | `/etc/php/X.Y` | ✅ 13 trixie `8.4.27-1~deb13u1` ([DSA-6574-1](https://security-tracker.debian.org/tracker/CVE-2026-109618)), ✅ 12 bookworm `8.2.35-1~deb12u1` (DLA-4848-1), ✅ sid `8.4.27-1`. ⏳ forky (testing) still `8.4.26-1`. 11: no free fix | `apt upgrade` |
| **RHEL / Rocky** AppStream | `/etc/php.ini` | 🔄 RHEL 9: [RHSA-2026:87072](https://access.redhat.com/errata/RHSA-2026:87072) php:8.2 → `php-8.2.35-1.module+el9.8.0+25111+a1450321`, [RHSA-2026:87079](https://access.redhat.com/errata/RHSA-2026:87079) php:8.3 → `php-8.3.36-1.module+el9.8.0+25109+6886e21a`. ⏳ other streams and RHEL 8 / 10 ([RHSB-2026-013](https://access.redhat.com/security/vulnerabilities/RHSB-2026-013), updated 22 Oct 01:41). RHEL 7 is not affected per Red Hat. Rated *Important* (FPM, not mod_php). UBI-based images and OpenShift Dev Spaces: rebuild when the base image updates | `dnf upgrade 'php*'`, `dnf updateinfo list --security` |
| **AlmaLinux** | `/etc/php.ini` | 🔄 [every stream in **almalinux-testing**](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/) (retired ones too), production next. Old version numbers with `.alma.1`, e.g. 9: `php-8.0.30-8.el9_8.alma.1`, 10: `php-8.3.33-1.el10_2.alma.1`. 8 php:7.4 (`php-7.4.33-8.module_el8.10.0+4321+cf5fd4bb`) is already in production | `dnf install -y almalinux-release-testing && dnf upgrade 'php*' --enablerepo=almalinux-testing`. Check with `rpm -q php-common`, not `php -v` |
| **Amazon Linux** | `/etc/php.ini` | ✅ AL2023 since 22 Oct: php8.2 ALAS2023-2026-3301, php8.3 -3302, php8.4 -3303, php8.5 -3304 ([ALAS](https://explore.alas.aws.amazon.com/CVE-2026-109618.html)). ❌ AL2023 php8.1: no fix planned. ✅ AL2 Extras php8.2 (ALAS2PHP8.2-2026-015); AL2 core php: no fix planned. Elastic Beanstalk PHP platform v4.13.12 carried settings only; a release with the upstream fix was targeted for 22 Oct. **Lightsail** instances can't be updated in place: create a new one from the updated blueprint | AL2023: `dnf check-release-update`, then `dnf upgrade --releasever=latest`. AL2: `yum update 'php*'` |
| **Alpine** | `/etc/php8X` | ✅ 3.24 and edge (x86_64, aarch64): php83 `8.3.36-r0`, php84 `8.4.27-r0`, php85 `8.5.12-r0` ([secdb](https://secdb.alpinelinux.org/)). ❌ 3.23 and older won't get a fix (Alpine developer) | `apk upgrade`; on 3.23 and older, move to 3.24 |
| **Remi** | `/etc/opt/remi`, `/opt/remi` | ✅ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 on rpms.remirepo.net (21 Oct, evening). Some mirrors lag. The earlier 8.4.27RC1 / 8.5.12RC1 builds do **not** contain the fix | `dnf clean metadata && dnf upgrade 'php*'` (SCL: `'php8[0-9]-*'`) |
| **LiteSpeed lsphp** (LiteSpeed repo, CyberPanel) | `/usr/local/lsws/lsphpXY` | ⏳ no fixed lsphp build confirmed on 22 Oct ([OpenLiteSpeed #532](https://github.com/litespeedtech/openlitespeed/issues/532)). `apt upgrade 'php*'` doesn't touch lsphp | `apt-get install --only-upgrade 'lsphp*'` / `dnf upgrade 'lsphp*'`, check the version, then `lswsctrl restart` |
| **Docker `php` image** | inside the image | ✅ `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12` tags on Docker Hub (from 21 Oct, ~17:30 UTC). `*RC1` tags don't contain the fix | `docker build --pull`, then `docker compose up -d --force-recreate`. Check with `docker run --rm php:8.4-fpm php -v` |
| Gentoo / Arch / Homebrew / windows.php.net | — | ✅ (Arch: 8.3, 8.5 only) | package manager / download |
| FrankenPHP, Chainguard images, Bref, Heroku | — | ✅ (FrankenPHP v1.13.2) | update the binary / image / buildpack |
| Aikido images (`public.ecr.aws/aikido-dev/php`) | inside the image | ✅ free backported images that keep the old tag, e.g. `php:8.4.26-fpm-trixie`, `php:8.3.35-cli`, `php:7.4.33-fpm`, `php:7.3.33-fpm`. No 8.0 / 8.1 yet | for pinned old tags you can't move yet. The version string stays old, so `php -v` and `--check` can't prove the fix: trust the vendor or move to 8.x.y fixed tags |
| **Fedora** | — | ✅ 44: PHP 8.5.12 (FEDORA-2026-a9eba4bbc3) | `dnf upgrade --refresh 'php*'` |
| SUSE / openSUSE | — | ⏳ no advisory found on 22 Oct. SUSE backports at the same version number | `zypper lp --cve=CVE-2026-109618`, then `zypper patch` |
| **Local dev stacks**: MAMP, XAMPP, Laragon, static-php-cli, NativePHP, swoole-cli, ServBay macOS v2 | — | ❌ not fixed (21 Oct). ✅ Laravel Herd, ServBay v1 | don't expose them to the internet; XAMPP hasn't shipped since 2023 |

**Backports keep the old version number.** Ubuntu's `8.3.6-0ubuntu0.24.04.13` is fixed even though it says 8.3.6. `--check` compares Ubuntu's own builds with the USN table below (`dpkg --compare-versions`), and reads the package changelog for the CVE ids on other distros (AlmaLinux's testing build `php-cli-8.0.30-8.el9_8.alma.1` is recognised this way). Debian and sury changelogs may not list the CVEs, but their upstream numbers (8.2.35, 8.4.27 and so on) are new enough. **DirectAdmin** patches 7.4 / 8.0 / 8.1 without changing the version number: `--check` reports those as PATCHED when the binary was built after CustomBuild's CVE patch, and tells you to run `da build php` when it wasn't. **cPanel** does the same for ea-php74 / 80 / 81: `--check` reads the package release (`7.4.33-19` and up is fixed). **CloudLinux's** ea-php builds are numbered differently (`*.cloudlinux.N`), so `--check` reads their changelog instead.

### Ubuntu

Canonical has shipped fixes for every release ([announcement](https://ubuntu.com/blog/php2shell-vulnerability-fixes-available), USN-8948-1 / USN-8948-2):

| Release | Package | Fixed version | Channel |
|---|---|---|---|
| 26.10 Stonking | php8.5 | `8.5.9-0ubuntu2.1` | standard |
| 26.04 LTS Resolute | php8.5 | `8.5.4-0ubuntu1.5` | standard |
| 24.04 LTS Noble | php8.3 | `8.3.6-0ubuntu0.24.04.13` | standard |
| 22.04 LTS Jammy | php8.1 | `8.1.2-1ubuntu2.28` | standard |
| 20.04 LTS Focal | php7.4 | `7.4.3-4ubuntu2.29+esm5` | **Ubuntu Pro (ESM)** |
| 18.04 LTS Bionic | php7.2 | `7.2.24-0ubuntu0.18.04.17+esm14` | **Ubuntu Pro (ESM)** |
| 16.04 LTS Xenial | php7.0 | `7.0.33-0ubuntu0.16.04.16+esm22` | **Ubuntu Pro (ESM)** |
| 14.04 LTS Trusty | php5 | `5.5.9+dfsg-1ubuntu4.29+esm18` | **Ubuntu Pro (ESM)** |

```bash
apt list '?installed ?name(^php[0-9.]+$)'                                        # what you have
sudo apt update && sudo apt install --only-upgrade '?name(^php[0-9.]+$)' '?name(^php[0-9.]+-)'
sudo pro attach <token>     # 20.04 and older only: Ubuntu Pro is free for up to 5 machines
```

- These are Ubuntu's own builds. **On ondrej/sury packages** (versions with `deb.sury.org`) this table doesn't apply. Those need 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.
- **unattended-upgrades** installs the fix within 24 hours, but **doesn't restart PHP**. Restart PHP-FPM and Apache yourself, or reboot. `--check` reports workers that still run the replaced code.
- `--check` also applies to 20.04 and older: an ESM build at or above the table is PATCHED, and an older one is reported with the `pro attach` hint.

### Commands

```bash
# Debian / Ubuntu (distro packages or packages.sury.org)
apt-get update && apt-get install --only-upgrade $(dpkg-query -W -f='${binary:Package}\n' '*php*')
# RHEL family / Remi / cPanel EA4 / CloudLinux alt-php
dnf upgrade 'php*' 'ea-php*' 'alt-php*'        # yum on EL7
# Plesk
plesk installer update
# DirectAdmin
da build update && da build php
```

### Restart, or the update doesn't count

Running workers keep the old PHP in memory until they're replaced.

| How PHP runs | After the update |
|---|---|
| PHP-FPM | `systemctl restart php8.3-fpm` (RHEL: `php-fpm`; Plesk: `plesk-php83-fpm`; cPanel: `ea-php83-php-fpm`) |
| Apache mod_php | **Full** `systemctl restart apache2` / `httpd`. A graceful reload keeps the old `libphp` loaded |
| LiteSpeed | `/usr/local/lsws/bin/lswsctrl restart` |
| Docker | Recreate the container from the new image. A restart keeps the old image |
| Queue workers, Octane, Swoole, RoadRunner, cron daemons | Restart them (`php artisan queue:restart`; Octane needs a process restart) |

`--check` finds PHP, Apache and LiteSpeed processes that still map **replaced (deleted) PHP files** and reports them as not patched, with the process names to restart. Manual equivalent: `grep -lE ' /[^ ]*php[^ ]* \(deleted\)$' /proc/[0-9]*/maps`.

If you set `memory_limit = -1` as an interim measure, set a real limit again after patching. The patched build has a hard OOM limit, and processes that hit it exit with code 137. `--check` warns about FPM builds that are still at `-1`.

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
- **Multipart is not the only way in.** Datadog reached the OOM path with a plain `application/x-www-form-urlencoded` POST: one field name of about 3.5 MB, plus an empty-named field holding NUL bytes. A multipart block doesn't stop that. Cap request bodies too (nginx `client_max_body_size 8m`, Apache `LimitRequestBody 8388608`, larger only on upload paths). `--waf-print` adds ModSecurity rules for parameter names over 1 KB and NUL bytes in parameters. Your WAF body-inspection limit (`SecRequestBodyLimit`) must be at least that large, or the rule never sees the field.
- **Watch responses, not just requests.** The CVE-2026-109618 memory leak sends freed worker memory (passwords, API keys, session tokens of other users) back URL-encoded in a `PHPSESSID` `Set-Cookie`, even if the app never calls `session_start()` ([Wiz](https://www.wiz.io/blog/php2shell-php-rce), [Sansec](https://sansec.io/research/php2shell)). No code runs on the host, so EDR and process rules can't see it. `--waf-print` adds a ModSecurity phase-3 rule that blocks any `PHPSESSID` cookie that isn't a plain ID (`[0-9A-Za-z,-]`, 16–256 chars) or a logout (`deleted`). If you renamed `session.name`, edit the rule. If the leak may already have happened, rotate the secrets the PHP process can read.
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
- **Old distros.** Ubuntu 20.04 and older get the fix only through Ubuntu Pro (ESM), see [Ubuntu](#ubuntu). Debian 11, Amazon Linux 2 core PHP and AL2023 php8.1 get none. Distro backports keep the upstream version number, so compare the package revision against your distro's security advisory (`--check` looks for the CVE ids in the package changelog).

## Interim measures php-fix does NOT apply (decide yourself)

The advisories list more measures. php-fix leaves them out because each one can take a server down or break apps:

| Measure | From | Why it isn't automatic |
|---|---|---|
| `memory_limit = -1`, set with `php_admin_value` | 109618 | Removes the predictable per-request limit the exploit relies on. Still incomplete. **It also removes the only per-request memory cap,** so one runaway script can eat the host's RAM. Use it only with per-worker cgroup limits (`memory.max`). A cgroup shared by the master and its workers takes them all down together |
| `pm.max_requests = 1` | 109619 | Stops worker reuse, so stale state doesn't reach the next request. Forks a process per request, which costs a lot of CPU |
| Lower `max_input_nesting_level` (32), `max_input_vars` (1000), `max_file_uploads` (5), `max_multipart_body_parts` (200) and `post_max_size` (8M, 32M with uploads; `upload_max_filesize` below it) | 109618 | Breaks large forms and multi-file uploads, depending on the app. Values from [php2shell.uk](https://php2shell.uk/mitigations) |
| `file_uploads = Off` | 109618 | Only for sites that take no uploads at all. Not the same as rejecting multipart at the web server, which stops PHP from parsing the body |
| A cgroup memory cap for PHP (`systemctl edit php8.3-fpm`: `MemoryHigh=3G`, `MemoryMax=4G`; containers: `docker run --memory=4g`) | 109618 | Needed with `memory_limit = -1`. Sizing depends on the host. **Never** use `ulimit -v` / `-d`, systemd `LimitAS=` / `LimitDATA=` or Apache `RLimitMEM` instead: they make allocations fail inside PHP, which is the vulnerable path. `--interim` reports both |
| `pm.max_requests = 50` (instead of 1) | 109619 | Cheaper middle ground: corrupted state survives at most 50 requests. No effect on single-request attacks |
| Remove deprecated / invalid values from per-request INI overrides (`.htaccess` / Apache `php_value`, nginx `fastcgi_param PHP_VALUE`) | 109619 | Needs review of each site. `--audit` lists web server configs that pass `PHP_VALUE` |
| Stop attacker-reachable fatal errors and timeouts | 109619 | Application work |

Run `--interim` to see which of these are in effect on each running pool, not just in `php.ini`.

### Reducing exposure beyond PHP settings

The PHP team says ini settings won't save you. If patching has to wait, these cut the exposure itself. They come from the PHP team, CERT-EU and the write-ups linked below:

- **Take it off the internet** for the time being. Admin panels, staging, phpMyAdmin and internal apps behind a VPN or an authenticating reverse proxy. CERT-EU and the UK NCSC advise taking unpatched internet-facing PHP offline.
- **Serve a static maintenance page from the web server**, with PHP-FPM stopped. An in-app maintenance mode runs after PHP has already parsed the request.
- **Allow only GET and HEAD** where a site doesn't need forms.
- **Multipart only where uploads happen.** Reject `multipart/form-data` everywhere else (`--waf-print`), and keep body caps low (`client_max_body_size`, `LimitRequestBody`). Enforce limits on decoded bodies and on requests without `Content-Length` at the proxy.
- **Put a CDN / WAF in front, and lock the origin** to its IP ranges so nobody can go around it.
- **Contain a compromise:** one pool and one system user per site, web roots read-only to that user, no secrets readable that the site doesn't need, outbound traffic from web servers limited to what they really use (egress firewall), and SELinux / AppArmor in enforcing mode.
- **`disable_functions`** for the shell-execution family (`exec`, `system`, `shell_exec`, `passthru`, `proc_open`, `popen`, `pcntl_exec`) on sites that don't need them. It raises the cost of a compromise; it doesn't stop the memory corruption.
- **Ask your host** for a patch date if you're on managed or shared hosting, and check bundled PHP in vendor appliances, CI runners and local dev stacks.

None of this needs php-fix. Undo it after patching (see the [checklist](#after-patching-checklist)).

## Rollback

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash -s -- --revert
```

This restores every file from the most recent run's backups, removes the mod_php and PHP 8.5 drop-ins and reloads services gracefully. Backup files are kept. Pass `--revert=20261021-120000` to restore a specific run, or add `--dry-run` to preview the revert first.

## After patching: checklist

Work through this once per server. Each step is a command you run yourself.

1. **Confirm the fix is live, not just installed.** `--check` must show PATCHED for every binary, every running FPM pool and every PHP container, and must not print "Still running replaced (old) PHP code". If it does, restart those services. mod_php needs a full Apache restart, not a graceful reload.
2. **Check every PHP source on the host.** Panels run several PHP builds side by side (Plesk, cPanel/CloudLinux ea-php, alt-php, DirectAdmin `/usr/local/phpXY`, Remi SCL). One unpatched version used by one site is enough.
3. **Rebuild images, don't just restart them.** `docker build --pull --no-cache`, then recreate the containers. Check CI pipelines and base images pinned to an old digest or tag.
4. **Undo the interim measures you set by hand:**
   - `memory_limit = -1` → back to a finite value. Fixed PHP now kills the worker at the hard limit (exit 137) and skips shutdown handlers.
   - `pm.max_requests = 1` → back to your normal value (it costs a fork per request).
   - Temporary `post_max_size` / `upload_max_filesize` cuts that broke uploads.
   - Edge rules that block all multipart → remove, or narrow them to the paths that never take uploads.
5. **Keep the cheap hardening.** Leave `session.upload_progress.enabled = Off` unless an app needs upload progress bars. On PHP 8.5, `zz-php2shell.ini` can stay or go. `display_errors = Off` in production.
6. **Clear old sessions.** Session files written before the patch may hold attacker-controlled data. Deleting them logs everyone out: remove `sess_*` in `session.save_path` (or flush the session keys in Redis / Memcached) once, after the update.
7. **Look for compromise during the exposure window.** Run `--audit=exposure` (back to the first attack on 17 Oct), then a malware scan of the web roots (see [Existing protection tools](#existing-protection-tools)). Patching doesn't remove a webshell, cron job or SSH key planted before the update.
8. **Rotate secrets if anything looks wrong**, or if the server was internet-facing and unpatched for a long time. The bugs can leak worker memory: database passwords, API keys, app keys (`APP_KEY`, WordPress salts), payment and mail credentials. Rotate them and invalidate sessions and tokens.
9. **Write down what you run.** PHP versions per server and their source, so the next advisory takes minutes. `--check --json` gives you a fleet inventory.

## Existing protection tools

php-fix closes config paths and reports patch status. It doesn't watch traffic or processes. These established tools do, and they're kept current by their vendors. They don't replace patching.

| Tool | Where it helps | Getting started |
|---|---|---|
| **Cloudflare WAF** | Blocks known php2shell exploit traffic at the edge. Free plans included (Managed Free Ruleset) | Make sure the managed rules are on (paid plans: Cloudflare Managed Ruleset in block mode). Review hits under Security → Events. Allow only [Cloudflare IPs](https://www.cloudflare.com/ips/) to reach the origin, or attackers can go around it |
| **Imunify360** (cPanel, Plesk, DirectAdmin, CloudLinux) | ModSecurity vendor rules: 8.83 blocks the public exploit, 8.84 the tool signature and off-site upload-progress posts (LiteSpeed too), 8.85 more variants. No rule covers the OOM path. Scanning IPs get a CAPTCHA | `imunify360-agent update --force modsec-rules`. `--check` reports the ruleset version and asks for 8.85 or later. Off-site upload forms and stripped `Referer` headers can trip 8.84 |
| **ImunifyAV** (free) / **Linux Malware Detect** / **ClamAV** | Finding webshells and droppers after the fact | ImunifyAV: install from the panel's plugin page. maldet: `maldet -a /var/www`. ClamAV: `clamscan -ri /var/www` |
| **ModSecurity + OWASP CRS** | Generic web attack rules on your own Apache / nginx. Not php2shell-specific | Debian / Ubuntu Apache: `apt install libapache2-mod-security2 modsecurity-crs`, then copy `/etc/modsecurity/modsecurity.conf-recommended` to `modsecurity.conf`. Start in `DetectionOnly`, watch the audit log for false positives, then switch to `SecRuleEngine On` |
| **CrowdSec** | Reads web server logs, bans abusive IPs, and shares a blocklist | Install from [crowdsec.net](https://docs.crowdsec.net/), add the nginx or apache2 collection (`cscli collections install crowdsecurity/nginx`) and a firewall bouncer. Check the hub for PHP-related scenarios: `cscli hub update && cscli scenarios list -a \| grep -i php` |
| **Wazuh / OSSEC**, **Falco**, a commercial EDR | File integrity in web roots, unusual processes started by the web server user, outbound connections | Follow the vendor's guide. Watch especially for PHP workers starting shells or downloaders and new `.php` files under upload / cache / tmp directories |
| **AWS WAF** | The managed PHP rule group (version 2.3, now the default) has a php2shell rule; `AWSManagedRulesCommonRuleSet` `SizeRestrictions_BODY` blocks bodies over 8 KB | Check that the PHP rule group is on 2.3. `--waf-print` adds a custom rule that blocks multipart on any method (AWS's sample only matches POST + `PHPSESSID`). ALB inspects only the first 8 KB of a body |
| **Check Point, Imperva, Fastly, Google Cloud Armor** and other WAF vendors | Vendor signatures for php2shell | Enable the vendor's php2shell protection in blocking mode. Imperva: Cloud WAF on by default, Elastic WAF 2.2.1+, WAF Gateway V14.7 LTS / V15.5 LTS with the ADC content update |

Before you switch on blocking:

- **Start in log-only mode** (ModSecurity `DetectionOnly`, CrowdSec simulation) and watch for false positives on uploads, logins and payment callbacks.
- **Behind a proxy or CDN**, make sure the real client IP is in the logs (nginx `real_ip`, Apache `mod_remoteip`). Otherwise a ban hits the proxy and takes the whole site down.
- **Allowlist your own IPs** and monitoring, payment and webhook providers before enabling IP bans.

## Other tools and write-ups

| Resource | What it's for |
|---|---|
| [syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection) | Apache `.htaccess` multipart block with a test page that checks whether multipart still reaches PHP |
| [0xrsydn/php2shell-scan](https://github.com/0xrsydn/php2shell-scan) | Read-only **external** reachability check: does PHP still parse attacker multipart pre-auth? Supports before/after-patch baselines. Use it to verify your edge rules from outside |
| [mikensec/php2shell-lab](https://github.com/mikensec/php2shell-lab) | Offline lab for analysing a PoC sample and building detection rules (no exploit included) |
| [Lexsah/php2shell-detection](https://github.com/Lexsah/php2shell-detection) | Community Sigma, YARA, Suricata, ModSecurity, Falco and auditd rules (scanner UA, upload-progress field, shells spawned by php-fpm / Apache). Some rules are only syntax-checked |
| [darkfibr/php2shell-detect](https://github.com/darkfibr/php2shell-detect) | Request-shape scanner for logs that doesn't rely on the user agent, Suricata / Snort rules, YARA for the public PoC scripts |
| [Ademking/php2shell-nuclei-templates](https://github.com/Ademking/php2shell-nuclei-templates) | Nuclei templates. **The two "critical" templates write session files on the target**: use them only against your own systems |
| [Florian Roth's process-watcher](https://github.com/Neo23x0/process-watcher) | Recommended by Huntress for watching PHP workers spawning shells when you have no EDR |
| [Censys query gist](https://gist.github.com/silascutler/c7f04537a79ace89569f979d964af0f9) | Finding exposed PHP hosts |
| [Vincent Schmalbach's write-up](https://www.vincentschmalbach.com/cve-2026-109618-and-cve-2026-109619-what-you-should-do-now/) | Container-tested rules for nginx, Apache, LiteSpeed, Caddy, FrankenPHP, HAProxy and Cloudflare, plus a list of what doesn't help |

Timeline note: the fix and advisories are public, so the patch diff now shows attackers where the bugs are, and mass scanning is under way. Patch first, then run `--audit=exposure`.

**Hunting with your own EDR / SIEM** ([Elastic's write-up](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection) has ready queries):
- a non-interactive web or PHP process (`apache2`, `httpd`, `php-fpm*`, `php-cgi`, `lsphp*`, `frankenphp`) starting `sh -c` / `bash -c`
- recon commands run as the web user: `id`, `whoami`, `uname -a`, `hostname`, `sudo -l`, `find / -perm -u=s`
- `curl … | sh`, `wget -qO- … | sh`, `base64 -d | sh`
- reads of `.env`, `~/.aws/credentials` and Kubernetes service account tokens, or calls to `169.254.169.254`
- new high-entropy `.php` files under the web root

## References

- [PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 release announcement](https://www.php.net/)
- [GHSA-w8hw-w9fx-j79w / CVE-2026-109618: RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp / CVE-2026-109619: RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Help Net Security: PHP2Shell patched](https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/)
- [Tenable FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [Plesk advisory](https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-Remote-code-execution-in-PHP-shipped-with-Plesk)
- [Ubuntu: php2shell fixes available (USN-8948-1 / USN-8948-2)](https://ubuntu.com/blog/php2shell-vulnerability-fixes-available)
- [ma.ttias.be: per-repository patch status and restart guide](https://ma.ttias.be/php-cve-2026-109618-patch/)
- [DirectAdmin forum: Critical PHP updates (staff release notes on page 3)](https://forum.directadmin.com/threads/critical-php-updates.82726/page-3)
- [Debian security tracker: CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618)
- [CloudLinux: Imunify360 ruleset 8.83](https://blog.cloudlinux.com/php-cve-2026-109618-and-cve-2026-109619)
- [docker-library/php#1694](https://github.com/docker-library/php/pull/1694)
- [NCSC-NL php2shell operational info](https://github.com/NCSC-NL/php2shell)
- [cPanel EasyApache 4 change log (25.91)](https://docs.cpanel.net/changelogs/easyapache-4-change-log-25/)
- [AlmaLinux: php2shell patches (testing package versions)](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/)
- [RHSA-2026:87072: php:8.2 on RHEL 9](https://access.redhat.com/errata/RHSA-2026:87072)
- [Red Hat bulletin RHSB-2026-013](https://access.redhat.com/security/vulnerabilities/RHSB-2026-013)
- [Datadog Security Labs: detection, analysis and remediation](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [php2shell.uk: temporary mitigations with values](https://php2shell.uk/mitigations)
- [flyingpenguin: PHP2Shell, ini won't save you](https://www.flyingpenguin.com/php2shell-ini-wont-save-you/)
- [MVPS.net: temporary mitigations](https://www.mvps.net/docs/php2shell-temporary-mitigations-and-the-urgent-php-security-update)
- [Cloudflare: php2shell WAF protection](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/)
- [php2shell.com: overview, signals and after-patch notes](https://www.php2shell.com/)
- [Amazon Linux 2023 issue #1148](https://github.com/amazonlinux/amazon-linux-2023/issues/1148)
- [Alpine secdb](https://secdb.alpinelinux.org/)
- [BleepingComputer: PHP ships emergency patches (Cloudflare early attacks)](https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/)
- [watchTowr FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [Check Point: what we know (IPS CPAI-2026-15172)](https://blog.checkpoint.com/security/php2shell-what-we-know-about-the-leaked-critical-php-vulnerabilities-cve-2026-109618-cve-2026-109619)
- [SOCRadar: exploitation claims and hunting](https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/)
- [CloudLinux status](https://cloudlinux.statuspage.io/)
- [PHP-UP-2026: pre-release write-up (heap UAF in session upload progress)](https://jackalsyn.com/posts/php-up-2026.html)
- [php2shell overview: SecureLayer7](https://blog.securelayer7.net/php-rce-cve-2026-109618-109619/)
- [Disabling session.upload_progress before the php2shell patch lands](https://lilting.ch/en/articles/php2shell-session-upload-progress-uaf)
- [Assessing and containing php2shell: DeXpose](https://www.dexpose.io/php2shell-php-rce-exposure-response/)
- [Apache-level multipart blocking toolkit: syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection)
- [Sansec: Critical PHP RCE](https://sansec.io/research/php2shell)
- [Aikido: patched images and exposure checker](https://www.aikido.dev/blog/critical-vulnerabilities-in-php-php2shell)
- [Wiz: PHP2Shell write-up (PHPSESSID memory leak)](https://www.wiz.io/blog/php2shell-php-rce)
- [PHP2Shell detection opportunities (Sigma / Suricata / ModSecurity / Falco)](https://gist.github.com/Blevene/472692937d05145d29d17dc3c6edc2a0)
- [deb.sury.org issue #145: arm64 build status](https://codeberg.org/oerdnj/deb.sury.org/issues/145)
- [Huntress: Rapid Response, php2shell](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
- [Vincent Schmalbach: what you should do now](https://www.vincentschmalbach.com/cve-2026-109618-and-cve-2026-109619-what-you-should-do-now/)
- [Amazon Threat Intelligence: exploitation before disclosure in MadPot (17 Oct)](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
- [AWS: using AWS WAF to mitigate php2shell](https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/)
- [AWS Security Bulletin 2026-143-aws](https://aws.amazon.com/security/security-bulletins/2026-143-aws/)
- [VulnCheck: observed activity, IOCs and exploit status](https://www.vulncheck.com/blog/php2shell-vulnerabilities)
- [Imperva: five exploitation techniques](https://www.imperva.com/blog/php2shell-vulnerability-updates/)
- [Red Hat: CVE-2026-109618](https://access.redhat.com/security/cve/cve-2026-109618)
- [RHSA-2026:87079: php:8.3 on RHEL 9](https://access.redhat.com/errata/RHSA-2026:87079)
- [watchTowr: PHP2Shell exploited](https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/)
- [Fedora 44: FEDORA-2026-a9eba4bbc3](https://linuxsecurity.com/advisories/fedora/fedora-44-php-2026-a9eba4bbc3)
- [SecurityWeek: exploitation started days before patches (Cloudflare volumes)](https://www.securityweek.com/php2shell-exploitation-started-days-before-patches/)
- [Elastic Security Labs: detection coverage and hunting queries](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection)
- [Recorded Future: exploitation and PoC landscape](https://www.recordedfuture.com/blog/php2shell-vulnerability-exploitation)
- [JFrog: all you need to know (fake PoCs)](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/)
- [AhnLab ASEC: php2shell repositories on GitHub](https://asec.ahnlab.com/en/95944/)
- [Patchstack: attacks ongoing](https://patchstack.com/articles/php-major-vulnerability-alert-10-2026/)
- [OpenLiteSpeed issue #532](https://github.com/litespeedtech/openlitespeed/issues/532)

## License

MIT. No warranty: test on staging first and keep the backups.
