#!/usr/bin/env bash
# php-fix: emergency mitigation for php2shell (CVE-2026-109618 / CVE-2026-109619)
# Sets session.upload_progress.enabled = Off in every PHP install on the host.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash
#   ... | sudo bash -s -- --dry-run      # show what would change, change nothing
#   ... | sudo bash -s -- --no-restart   # do not reload PHP / web services
#   ... | sudo bash -s -- --check        # read-only: patched / unpatched / EOL per PHP binary
#   ... | sudo bash -s -- --audit        # read-only: quick indicator-of-compromise sweep
#   ... | bash -s -- --waf-print         # print WAF / proxy rules for the multipart path, change nothing
#   ... | sudo bash -s -- --revert       # restore the backups of the last run
#   ... | bash -s -- --probe=https://example.com/index.php   # check from outside that multipart is blocked
#   ... | bash -s -- --user-ini=$HOME/public_html            # shared hosting, no root: write .user.ini
#
# This is a stopgap. The real fix is upgrading PHP to the patched release.

set -u

VERSION="1.4.0"
DIRECTIVE="session.upload_progress.enabled"
TS="$(date +%Y%m%d-%H%M%S)"
MODE=fix
DRY_RUN=0
NO_RESTART=0
REVERT_TS=""
AUDIT_HOURS=48
PROBE_URL=""
USERINI_DIR=""
JSON=0

# First release of each supported branch that contains the php2shell fix.
# Filled in from the official advisory; empty = not published yet.
PATCHED_VERSIONS=""
CVES="CVE-2026-109618|CVE-2026-109619"

usage() {
  cat <<EOF
php-fix $VERSION - php2shell (CVE-2026-109618 / CVE-2026-109619) mitigation

Usage: install.sh [mode] [options]

Modes (default: apply the mitigation):
  --check            Read-only. Report patched / unpatched / EOL for every PHP binary.
  --audit[=HOURS]    Read-only. Quick indicator-of-compromise sweep (default: last 48 h).
  --waf-print        Print WAF / proxy rules for the multipart path. Changes nothing.
  --revert[=STAMP]   Restore the backups of the last run (or of run STAMP, e.g. 20261021-120000).
  --probe=URL        From outside: does multipart still reach this PHP URL? (5 harmless requests)
  --user-ini=DIR     Shared hosting without root: set it in DIR/.user.ini (PHP-FPM / CGI / LiteSpeed).

Options:
  --dry-run          Show what would change, change nothing (fix / revert).
  --no-restart       Do not reload PHP / web services (fix / revert).
  --json             Machine-readable output (check).
  -h, --help         Show this help.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --dry-run)    DRY_RUN=1 ;;
    --no-restart) NO_RESTART=1 ;;
    --check)      MODE=check ;;
    --audit)      MODE=audit ;;
    --audit=*)    MODE=audit; AUDIT_HOURS="${arg#*=}" ;;
    --waf-print)  MODE=waf ;;
    --revert)     MODE=revert ;;
    --revert=*)   MODE=revert; REVERT_TS="${arg#*=}" ;;
    --probe=*)    MODE=probe; PROBE_URL="${arg#*=}" ;;
    --user-ini=*) MODE=userini; USERINI_DIR="${arg#*=}" ;;
    --json)       JSON=1 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "Unknown option: $arg"; usage; exit 1 ;;
  esac
done

case "$AUDIT_HOURS" in ''|*[!0-9]*) echo "--audit expects a number of hours"; exit 1 ;; esac
case "$REVERT_TS" in ''|[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;
  *) echo "--revert expects a stamp like 20261021-120000"; exit 1 ;; esac
case "$MODE:$PROBE_URL" in probe:http://?*|probe:https://?*|[!p]*) ;; *) echo "--probe expects an http(s) URL"; exit 1 ;; esac
[ "$MODE" = userini ] && [ ! -d "$USERINI_DIR" ] && { echo "--user-ini expects an existing directory"; exit 1; }

if [ -t 1 ]; then G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'; else G=''; Y=''; R=''; N=''; fi
# Messages carry file names, process args and log fields an attacker may control:
# print them literally and strip control characters (no terminal escape / fake-line injection).
# Drops invalid UTF-8 (incl. lone 8-bit C1 bytes like 0x9B = CSI), UTF-8 encoded C1 (U+0080-U+009F),
# then C0 controls and DEL. Without iconv, keep printable ASCII only.
# The C1 pattern is built from real bytes, so it doesn't depend on sed's \x escape support.
C1_RE="$(printf '\302[\200-\237]')"
if command -v iconv >/dev/null 2>&1; then
  clean() { printf '%s' "$*" | iconv -c -f UTF-8 -t UTF-8 2>/dev/null \
    | LC_ALL=C sed "s/$C1_RE//g" | LC_ALL=C tr -d '\000-\010\012-\037\177'; }
else
  clean() { printf '%s' "$*" | LC_ALL=C tr -cd '\011\040-\176'; }
fi
ok()   { printf "${G}[OK]${N} %s\n" "$(clean "$*")"; }
info() { printf "${Y}[..]${N} %s\n" "$(clean "$*")"; }
err()  { printf "${R}[!!]${N} %s\n" "$(clean "$*")"; }

# Expands to the array contents, or nothing if empty (safe under `set -u` on bash < 4.4, e.g. CentOS 7)
# usage: for x in ${ARR[@]+"${ARR[@]}"}; do ...

# ---------------------------------------------------------------------------
# --waf-print: rules for the second path (multipart parser). Prints only.
# ---------------------------------------------------------------------------
if [ "$MODE" = waf ]; then
  cat <<'EOF'
# php2shell: WAF / proxy rules for the multipart path.
# NOTHING has been changed. Review, adapt the upload allowlist to your apps, test on staging.
#
# - Match ANY method: PHP 8.4's request_parse_body() parses multipart on PUT/PATCH too.
# - Match "multipart" anywhere in Content-Type, case-insensitive (no ^ anchor, no exact type).
# - Allowlist entries are EXACT script paths (^...$). Never prefixes like ^/upload: they also
#   match /upload-anything.php. Every allowlisted path stays exposed.
# - Blocking multipart breaks file uploads, FormData/AJAX forms, Contact Form 7, Livewire...
#   outside the allowlist. A WAF only protects traffic that goes through it: lock the origin
#   down to the proxy/CDN IP ranges, or direct-to-IP requests skip it.
# - Do NOT block on the PHPSESSID cookie: it breaks sessions and doesn't stop the parser.

############ ModSecurity (v2 / v3) — narrow, safe for almost every site ############
# Blocks requests carrying the upload-progress field (session.upload_progress.name,
# default PHP_SESSION_UPLOAD_PROGRESS). Adjust if you changed that ini setting.
# ModSecurity's multipart parser is not PHP's: treat this as a filter, not a guarantee.
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
  "id:1026109,phase:2,deny,status:403,log,msg:'php2shell upload_progress probe'"

############ ModSecurity — broad: multipart only on allowlisted paths ############
SecRule REQUEST_HEADERS:Content-Type "@rx (?i)multipart" \
  "id:1026110,phase:1,deny,status:403,log,msg:'php2shell multipart outside allowlist',chain"
  SecRule REQUEST_FILENAME "!@rx ^/(wp-admin/async-upload\.php|wp-admin/media-new\.php)$" ""

############ nginx — multipart only on allowlisted paths ############
# http {} context:
map $http_content_type $php2shell_mp {
    default 0;
    "~*multipart" 1;
}
map $uri $php2shell_upload_ok {
    default 0;
    ~^/(wp-admin/async-upload\.php|wp-admin/media-new\.php)$ 1;
}
# inside EVERY server {} block that can reach PHP (server level, not only in location ~ \.php$):
#   set $php2shell "$php2shell_mp$php2shell_upload_ok";
#   if ($php2shell = "10") { return 403; }

############ Apache 2.4 — multipart only on allowlisted paths (server-wide, all vhosts) ############
# Save as /etc/apache2/conf-enabled/zz-php2shell-waf.conf (Debian/Ubuntu),
# /etc/httpd/conf.d/zz-php2shell-waf.conf (RHEL) or /etc/apache2/conf.d/zz-php2shell-waf.conf
# (cPanel), then `apachectl -t && apachectl graceful`. No mod_rewrite needed.
# The <If> sits inside <Location "/">, which Apache merges AFTER .htaccess files: a
# `Require all granted` or `RewriteEngine On` in any .htaccess cannot undo it.
# (A bare top-level <If> CAN be overridden by .htaccess. Keep the <Location> wrapper.)
<Location "/">
    <If "req('Content-Type') =~ /multipart/i && %{REQUEST_URI} !~ m#^/(wp-admin/async-upload\.php|wp-admin/media-new\.php)$#">
        Require all denied
    </If>
</Location>

############ Apache / LiteSpeed .htaccess (shared hosting, no server config access) ############
# Top of the site's .htaccess, above the CMS block. Caveat: a subfolder .htaccess with its own
# "RewriteEngine On" is NOT covered by this; the server-wide <Location> version above is.
RewriteEngine On
RewriteCond %{HTTP:Content-Type} multipart [NC]
RewriteCond %{REQUEST_URI} !^/(wp-admin/async-upload\.php|wp-admin/media-new\.php)$ [NC]
RewriteRule ^ - [F]

############ Caddy / FrankenPHP ############
# Inside the site block, in the same route/handle that runs php_fastcgi / php_server:
@php2shell {
    header_regexp Content-Type (?i)multipart
    not path /wp-admin/async-upload.php /wp-admin/media-new.php
}
respond @php2shell 403

############ HAProxy (frontend, above other http-request rules; not with TLS passthrough) ############
acl php2shell_mp req.hdr(content-type) -m sub -i multipart
acl php2shell_ok path /wp-admin/async-upload.php /wp-admin/media-new.php
http-request deny if php2shell_mp !php2shell_ok

############ Cloudflare (WAF custom rule expression, action: Block) ############
# (any(lower(http.request.headers["content-type"][*])[*] contains "multipart")
#  and not http.request.uri.path in {"/wp-admin/async-upload.php" "/wp-admin/media-new.php"})
# IP Access "Allow" rules skip custom rules. Restrict the origin to Cloudflare IP ranges.

############ Logging: record Content-Type so multipart traffic is visible ############
# Default access logs don't contain Content-Type, so multipart probing is invisible.
# These keep the "combined" layout and append ct="..."; `--audit` then reports multipart senders.
# nginx (http {} context; then use `access_log /var/log/nginx/access.log php2shell;`):
log_format php2shell '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
                     '"$http_referer" "$http_user_agent" ct="$http_content_type"';
# Apache (then `CustomLog ${APACHE_LOG_DIR}/access.log php2shell` in each vhost):
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" ct=\"%{Content-Type}i\"" php2shell
EOF
  exit 0
fi

if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ] && { [ "$MODE" = fix ] || [ "$MODE" = revert ]; }; then
  err "Run as root: curl ... | sudo bash"
  exit 1
fi

# Known PHP locations for distros and control panels
# (Debian/Ubuntu, RHEL/Remi, cPanel EA, CloudLinux alt-php, Plesk, aaPanel, LiteSpeed, DirectAdmin)
SEARCH_ROOTS=(/etc /usr/local/etc /usr/local/lib /usr/local/php* /opt/cpanel /opt/alt /opt/plesk/php /opt/remi /etc/opt/remi /www/server/php /usr/local/lsws)

existing_roots=()
for r in "${SEARCH_ROOTS[@]}"; do [ -d "$r" ] && existing_roots+=("$r"); done

ACTIVE_RE="^[[:space:]]*${DIRECTIVE//./\\.}[[:space:]]*="
ANY_RE="^[[:space:]]*;?[[:space:]]*${DIRECTIVE//./\\.}[[:space:]]*="
OFF_RE="^[[:space:]]*${DIRECTIVE//./\\.}[[:space:]]*=[[:space:]]*\"?(off|0|false|no|none)?\"?[[:space:]]*(;.*)?$"
POOL_RE="php_(admin_)?(value|flag)\[${DIRECTIVE//./\\.}\]"
POOL_OFF_RE="^[[:space:]]*${POOL_RE}[[:space:]]*=[[:space:]]*\"?(off|0|false|no|none)?\"?[[:space:]]*(;.*)?$"
MODPHP_CONFS=(/etc/apache2/conf-available/zz-php2shell.conf /etc/httpd/conf.d/zz-php2shell.conf /etc/apache2/conf.d/zz-php2shell.conf)

CHANGED=0; SKIPPED=0; FAILED=0

# Refuse to write in directories a non-root user could write to (symlink planting).
dir_safe() {
  local dir; dir="$(dirname "$1")"
  if [ "$(stat -c %u "$dir" 2>/dev/null)" != "0" ] || [ -n "$(find "$dir" -maxdepth 0 -perm /022 2>/dev/null)" ]; then
    err "Unsafe directory (not root-owned or group/world-writable), skipping: $dir"; return 1
  fi
}

# Never write the backup through an existing file or symlink.
backup() {
  local dst="$1.bak-$TS"
  dir_safe "$1" || return 1
  if [ -e "$dst" ] || [ -L "$dst" ]; then err "Backup path already exists: $dst"; return 1; fi
  cp -p --no-dereference "$1" "$dst"
}

APACHECTL="$(command -v apachectl || command -v apache2ctl || command -v httpd || true)"

reload_services() {
  [ "$DRY_RUN" -eq 0 ] && [ "$NO_RESTART" -eq 0 ] && [ "$CHANGED" -gt 0 ] || return 0
  # Never reload Apache with a broken config: a failed reload would take sites down.
  local apache_ok=1
  if [ -n "$APACHECTL" ] && ! "$APACHECTL" -t >/dev/null 2>&1; then
    apache_ok=0; err "Apache config test fails (was it already broken?), not reloading Apache"
  fi
  info "Reloading PHP / web services..."
  if command -v systemctl >/dev/null 2>&1; then
    local s
    mapfile -t SVCS < <(systemctl list-units --type=service --no-legend 2>/dev/null \
      | awk '{for(i=1;i<=NF;i++) if($i ~ /\.service$/){print $i;break}}' \
      | grep -Ei '^(php.*fpm|ea-php.*|plesk-php.*|apache2|httpd|lsws|lshttpd|litespeed)\.service$')
    for s in ${SVCS[@]+"${SVCS[@]}"}; do
      case "$s" in apache2.service|httpd.service) [ "$apache_ok" -eq 1 ] || continue ;; esac
      systemctl reload-or-restart "$s" && ok "Reloaded: $s" || err "Could not reload: $s"
    done
  else
    for s in php-fpm php7.4-fpm php8.0-fpm php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm php8.5-fpm apache2 httpd; do
      case "$s" in apache2|httpd) [ "$apache_ok" -eq 1 ] || continue ;; esac
      service "$s" reload >/dev/null 2>&1 && ok "Reloaded: $s"
    done
  fi
  # LiteSpeed without a systemd unit: its own graceful restart respawns lsphp with the new ini
  # (never kill lsphp directly, that drops in-flight requests).
  if [ -x /usr/local/lsws/bin/lswsctrl ] && ! printf '%s\n' ${SVCS[@]+"${SVCS[@]}"} | grep -Eq '^(lsws|lshttpd|litespeed)\.service$'; then
    /usr/local/lsws/bin/lswsctrl restart >/dev/null 2>&1 && ok "LiteSpeed graceful restart" || err "LiteSpeed restart failed"
  fi
}

find_php_bins() {
  {
    command -v php 2>/dev/null
    ls /usr/bin/php[0-9]* /opt/cpanel/ea-php*/root/usr/bin/php /opt/alt/php*/usr/bin/php \
       /opt/plesk/php/*/bin/php /www/server/php/*/bin/php /usr/local/php*/bin/php \
       /opt/remi/php*/root/usr/bin/php /usr/local/lsws/lsphp*/bin/php 2>/dev/null
  } | while read -r b; do [ -x "$b" ] && readlink -f "$b"; done | sort -u
}

find_fpm_bins() {
  ls /usr/sbin/php-fpm* /usr/local/sbin/php-fpm /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
     /opt/remi/php*/root/usr/sbin/php-fpm /opt/alt/php*/usr/sbin/php-fpm /opt/plesk/php/*/sbin/php-fpm \
     /www/server/php/*/sbin/php-fpm /usr/local/php*/sbin/php-fpm 2>/dev/null \
  | while read -r b; do [ -x "$b" ] && readlink -f "$b"; done | sort -u
}

# prints "<binary>|<sapi>|<PHP_VERSION>|<effective value>" for every CLI and FPM binary
collect_bins() {
  local b ver v
  while read -r b; do
    [ -n "$b" ] || continue
    ver="$("$b" -r 'echo PHP_VERSION;' 2>/dev/null)" || continue
    v="$("$b" -r "echo ini_get('${DIRECTIVE}');" 2>/dev/null)"
    echo "$b|cli|$ver|$v"
  done < <(find_php_bins)
  while read -r b; do
    [ -n "$b" ] || continue
    ver="$("$b" -v 2>/dev/null | awk 'NR==1{print $2}')"
    [ -n "$ver" ] || continue
    v="$("$b" -i 2>/dev/null | awk -F' => ' -v d="$DIRECTIVE" '$1==d{print $2; exit}')"
    echo "$b|fpm|$ver|$v"
  done < <(find_fpm_bins)
}

# major*100+minor of a version string, or empty
branch_num() { local ma mi; IFS=. read -r ma mi _ <<< "$1"; case "$ma$mi" in *[!0-9]*|'') return ;; esac; echo $((ma*100+mi)); }
is_off() { case "$(echo "$1" | tr 'A-Z' 'a-z')" in ''|0|off|false|no|none) return 0 ;; esac; return 1; }
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# Distro builds (Debian, Ubuntu, RHEL...) often backport fixes without changing PHP_VERSION:
# look for the CVE ids in the owning package's changelog.
backported() {
  local b="$1" pkg
  if command -v dpkg >/dev/null 2>&1 && pkg="$(dpkg -S "$b" 2>/dev/null | head -1 | cut -d: -f1)" && [ -n "$pkg" ]; then
    zcat -f /usr/share/doc/"$pkg"/changelog.Debian.gz /usr/share/doc/"${pkg%-*}"-common/changelog.Debian.gz 2>/dev/null | grep -Eq "$CVES" && return 0
  fi
  if command -v rpm >/dev/null 2>&1 && pkg="$(rpm -qf "$b" 2>/dev/null)" && [ -n "$pkg" ]; then
    rpm -q --changelog "$pkg" 2>/dev/null | grep -Eq "$CVES" && return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# Real SAPI check: ask every running PHP-FPM pool over FastCGI what it sees
# (php.ini + pool php_admin_* overrides), without curl, cgi-fcgi or files in a web root.
# ---------------------------------------------------------------------------
FCGI_CLIENT='<?php
$a = $argv[1]; $script = $argv[2];
$s = @stream_socket_client($a[0] === "/" ? "unix://$a" : "tcp://$a", $en, $es, 3);
if (!$s) { echo "ERR:connect"; exit(1); }
stream_set_timeout($s, 5);
function rec($t, $c) { return chr(1).chr($t).pack("n", 1).pack("n", strlen($c))."\0\0".$c; }
function len($n) { return $n < 128 ? chr($n) : pack("N", $n | 0x80000000); }
$p = "";
foreach (array("SCRIPT_FILENAME" => $script, "SCRIPT_NAME" => "/".basename($script),
  "REQUEST_URI" => "/".basename($script), "DOCUMENT_ROOT" => dirname($script),
  "REQUEST_METHOD" => "GET", "QUERY_STRING" => "", "SERVER_PROTOCOL" => "HTTP/1.1",
  "GATEWAY_INTERFACE" => "CGI/1.1", "SERVER_SOFTWARE" => "php-fix") as $k => $v)
  $p .= len(strlen($k)).len(strlen($v)).$k.$v;
fwrite($s, rec(1, pack("nC", 1, 0)."\0\0\0\0\0").rec(4, $p).rec(4, "").rec(5, ""));
$out = "";
while (strlen($h = (string)stream_get_contents($s, 8)) === 8) {
  $r = unpack("Cv/Ct/nid/nlen/Cpad", $h);
  $c = $r["len"] ? (string)stream_get_contents($s, $r["len"]) : "";
  if ($r["pad"]) stream_get_contents($s, $r["pad"]);
  if ($r["t"] == 6) $out .= $c;
  if ($r["t"] == 3) break;
}
echo preg_match("/PHPFIX:[^\r\n]*/", $out, $m) ? $m[0] : "ERR:no-answer";'

# pool files (contain both listen= and pm=)
find_pool_files() {
  [ ${#existing_roots[@]} -gt 0 ] || return 0
  find "${existing_roots[@]}" -xdev -type f -name '*.conf' -print0 2>/dev/null \
    | xargs -0 -r grep -lE '^[[:space:]]*listen[[:space:]]*=' 2>/dev/null \
    | xargs -d '\n' -r grep -lE '^[[:space:]]*pm[[:space:]]*=' 2>/dev/null | sort -u
}

# prints "<pool>|<address>|<PHP_VERSION>|<value>" or "<pool>|<address>|ERR|<reason>"
fcgi_pools() {
  [ "$(id -u)" -eq 0 ] || return 0
  local cli dir pool addr out f
  cli="$(find_php_bins | head -1)"; [ -n "$cli" ] || return 0
  dir="/run/php-fix.$$"
  mkdir -m 755 "$dir" 2>/dev/null || return 0
  printf '%s' "$FCGI_CLIENT" > "$dir/client.php"
  echo "<?php echo 'PHPFIX:'.PHP_VERSION.'|'.ini_get('${DIRECTIVE}');" > "$dir/check.php"
  chmod 644 "$dir/check.php"
  while read -r f; do
    awk -F'=' '/^[[:space:]]*\[[^]]+\][[:space:]]*$/ { gsub(/[][[:space:]]/, ""); pool=$0 }
               /^[[:space:]]*listen[[:space:]]*=/ && pool != "global" { v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); print pool "|" v }' "$f"
  done < <(find_pool_files) | sort -u | while IFS='|' read -r pool addr; do
    case "$addr" in
      /*)          [ -S "$addr" ] || { echo "$pool|$addr|ERR|not running"; continue; } ;;
      *[!0-9]*:*)  addr="$(echo "$addr" | sed -E 's/^(\*|0\.0\.0\.0|\[::\]):/127.0.0.1:/')" ;;
      *[!0-9]*)    echo "$pool|$addr|ERR|unsupported listen address"; continue ;;
      *)           addr="127.0.0.1:$addr" ;;
    esac
    out="$(timeout 10 "$cli" -n "$dir/client.php" "$addr" "$dir/check.php" 2>/dev/null)"
    case "$out" in
      PHPFIX:*) out="${out#PHPFIX:}"; echo "$pool|$addr|${out%%|*}|${out#*|}" ;;
      *)        echo "$pool|$addr|ERR|no answer (stopped, chroot or open_basedir?)" ;;
    esac
  done
  rm -rf "$dir"
}

# ---------------------------------------------------------------------------
# --probe=URL: does multipart reach this PHP URL? (read-only, harmless requests)
# ---------------------------------------------------------------------------
if [ "$MODE" = probe ]; then
  command -v curl >/dev/null 2>&1 || { err "curl is required for --probe"; exit 1; }
  info "Probing $PROBE_URL with 5 harmless requests (no exploit payload). Only probe sites you are authorized to test."
  pc() { curl -sk -o /dev/null -m 20 -w '%{http_code}' "$@" "$PROBE_URL" 2>/dev/null; }
  c_get="$(pc)"; c_url="$(pc -d php_fix_probe=1)"
  [ "$c_get" = 000 ] && [ "$c_url" = 000 ] && { err "No answer from $PROBE_URL"; exit 2; }
  info "GET: $c_get | urlencoded POST: $c_url (baseline)"
  BLOCKED=1
  probe_one() {   # <label> <code>
    case "$2" in
      403|406|444|000|501)
        if [ "$2" != "$c_url" ]; then ok "$1: $2, blocked before PHP"; return; fi ;;
    esac
    err "$1: $2, REACHES the application (same path as a normal request)"; BLOCKED=0
  }
  probe_one "multipart POST" "$(pc -F php_fix_probe=1)"
  probe_one "multipart PUT" "$(pc -X PUT -F php_fix_probe=1)"
  probe_one "mixed-case Content-Type" "$(pc -H 'Content-Type: MuLtIpArT/form-data; boundary=phpfix' \
    --data-binary $'--phpfix\r\nContent-Disposition: form-data; name="php_fix_probe"\r\n\r\n1\r\n--phpfix--\r\n')"
  info "A 403 can also come from the app or a security plugin; an edge block is not a patch."
  [ "$BLOCKED" -eq 1 ] && exit 0
  exit 1
fi

# ---------------------------------------------------------------------------
# --user-ini=DIR: shared hosting without root (PHP-FPM / CGI / LiteSpeed read .user.ini)
# ---------------------------------------------------------------------------
if [ "$MODE" = userini ]; then
  if [ "$(id -u)" -eq 0 ]; then
    err "Run --user-ini as the site's own user, not root (root writing into a user-owned directory is unsafe)."
    err "As root, use the default mode instead: it locks every pool server-wide."
    exit 1
  fi
  f="${USERINI_DIR%/}/.user.ini"
  [ -L "$f" ] && { err "Refusing to write through symlink: $f"; exit 1; }
  if [ -f "$f" ] && grep -Eiq "$ACTIVE_RE" "$f" && ! grep -Ei "$ACTIVE_RE" "$f" | grep -Eivq "$OFF_RE"; then
    ok "Already Off: $f"
  elif [ "$DRY_RUN" -eq 1 ]; then
    info "[dry-run] Would set ${DIRECTIVE} = 0 in $f"
  else
    if [ -f "$f" ]; then cp -p "$f" "$f.bak-$TS" || { err "Backup failed: $f"; exit 1; }; fi
    if [ -f "$f" ] && grep -Eiq "$ANY_RE" "$f"; then
      sed -i -E "s/${ANY_RE}.*/${DIRECTIVE} = 0/I" "$f"
    else
      printf '\n; php-fix: php2shell (CVE-2026-109618 / CVE-2026-109619) mitigation\n%s = 0\n' "$DIRECTIVE" >> "$f"
    fi
    ok "Wrote ${DIRECTIVE} = 0 to $f$([ -f "$f.bak-$TS" ] && echo "  (backup: $f.bak-$TS)")"
  fi
  info "PHP picks it up within user_ini.cache_ttl (default 5 minutes). It applies to this directory and below."
  info "Works with PHP-FPM, CGI/FastCGI and LiteSpeed. Apache mod_php ignores .user.ini: there, add"
  info "  php_flag ${DIRECTIVE} off"
  info "to .htaccess instead, and load the site right after (under PHP-FPM that line causes a 500 error)."
  info "Verify: a temporary <?php var_export(ini_get('${DIRECTIVE}')); file must print '0' or ''. Delete it afterwards."
  exit 0
fi

# ---------------------------------------------------------------------------
# --check: read-only patch status report
# ---------------------------------------------------------------------------
# classify <PHP_VERSION> <effective value> [binary for backport lookup] -> sets STATUS, NOTE, MIT
classify() {
  local ver="$1" v="$2" b="${3:-}" n fixed="" p
  n="$(branch_num "$ver")"
  if [ -z "$n" ]; then STATUS=UNKNOWN; MIT=unknown; NOTE="could not read PHP version"; return; fi
  if is_off "$v" && [ "$n" -ge 504 ]; then MIT=on; else MIT=off; fi
  for p in $PATCHED_VERSIONS; do [ "$(branch_num "$p")" = "$n" ] && fixed="$p"; done
  if [ "$n" -lt 504 ]; then STATUS=LEGACY; MIT=impossible; NOTE="EOL, no patch, and the mitigation cannot apply (< 5.4). Upgrade PHP."
  elif [ -n "$fixed" ] && ver_ge "$ver" "$fixed"; then STATUS=PATCHED; NOTE=">= $fixed"
  elif [ -n "$b" ] && backported "$b"; then STATUS=PATCHED; NOTE="distro backport (CVE in package changelog)"
  elif [ "$n" -lt 802 ]; then STATUS=EOL; NOTE="EOL branch, no official patch expected. Upgrade PHP."
  elif [ -n "$fixed" ]; then STATUS=UNPATCHED; NOTE="fixed in $fixed"
  else STATUS=UNKNOWN; NOTE="fixed versions not known to this php-fix version"
  fi
}

JSON_ROWS=()
json_str() { local x; x="$(clean "$1")"; x="${x//\\/\\\\}"; printf '"%s"' "${x//\"/\\\"}"; }
# report <kind> <target> <version> <status> <mitigation> <note>
report() {
  if [ "$JSON" -eq 1 ]; then
    JSON_ROWS+=("{\"kind\":$(json_str "$1"),\"target\":$(json_str "$2"),\"php\":$(json_str "$3"),\"status\":$(json_str "$4"),\"mitigation\":$(json_str "$5"),\"note\":$(json_str "$6")}")
    return
  fi
  local line="$2 ($1 $3): $4, mitigation $5. $6"
  case "$4" in PATCHED) ok "$line" ;; UNKNOWN) info "$line" ;; *) err "$line" ;; esac
}

if [ "$MODE" = check ]; then
  [ "$JSON" -eq 1 ] || info "php-fix $VERSION patch status (read-only)"
  [ -z "$PATCHED_VERSIONS" ] && [ "$JSON" -eq 0 ] && info "Official fixed versions are not in this script yet; update php-fix after the advisory is out."
  UNPATCHED=0
  while IFS='|' read -r b sapi ver v; do
    classify "$ver" "$v" "$b"
    report "$sapi" "$b" "$ver" "$STATUS" "$MIT" "$NOTE"
    [ "$STATUS" = PATCHED ] || UNPATCHED=1
  done < <(collect_bins)

  # What each running FPM pool really sees (php.ini + pool overrides)
  while IFS='|' read -r pool addr ver v; do
    if [ "$ver" = ERR ]; then report fpm-pool "$pool @ $addr" "" UNKNOWN unknown "$v"; continue; fi
    classify "$ver" "$v"
    report fpm-pool "$pool @ $addr" "$ver" "$STATUS" "$MIT" "$NOTE"
    [ "$STATUS" = PATCHED ] || UNPATCHED=1
    [ "$MIT" = off ] && [ "$STATUS" != PATCHED ] && UNPATCHED=1
  done < <(fcgi_pools)

  # PHP inside running containers (read-only docker exec)
  if command -v docker >/dev/null 2>&1; then
    while read -r name; do
      [ -n "$name" ] || continue
      out="$(timeout 15 docker exec "$name" php -r "echo PHP_VERSION,'|',ini_get('${DIRECTIVE}');" 2>/dev/null)" || continue
      classify "${out%%|*}" "${out#*|}"
      report container "$name" "${out%%|*}" "$STATUS" "$MIT" "$NOTE Containers need a rebuilt image, not this script."
      [ "$STATUS" = PATCHED ] || UNPATCHED=1
    done < <(docker ps --format '{{.Names}}' 2>/dev/null)
  fi

  # Held / version-locked packages silently skip the security update
  held=""
  command -v apt-mark >/dev/null 2>&1 && held="$(apt-mark showhold 2>/dev/null | grep -i php)"
  command -v dnf >/dev/null 2>&1 && held="$held $(dnf -q versionlock list 2>/dev/null | grep -i php)"
  command -v yum >/dev/null 2>&1 && ! command -v dnf >/dev/null 2>&1 && held="$held $(yum -q versionlock list 2>/dev/null | grep -i php)"
  held="$(echo $held)"
  if [ -n "$held" ]; then
    UNPATCHED=1
    [ "$JSON" -eq 1 ] || err "Held / version-locked PHP packages will NOT be updated: $held"
  fi

  if [ "$JSON" -eq 1 ]; then
    printf '{"tool":"php-fix","version":%s,"host":%s,"time":%s,"patched_versions":%s,"held_packages":%s,"exit":%s,"results":[' \
      "$(json_str "$VERSION")" "$(json_str "$(hostname 2>/dev/null)")" "$(json_str "$(date -u +%Y-%m-%dT%H:%M:%SZ)")" \
      "$(json_str "$PATCHED_VERSIONS")" "$(json_str "$held")" "$UNPATCHED"
    (IFS=,; printf '%s' "${JSON_ROWS[*]+"${JSON_ROWS[*]}"}")
    printf ']}\n'
  fi
  exit "$UNPATCHED"
fi

# ---------------------------------------------------------------------------
# --audit: read-only indicator-of-compromise sweep (heuristic, low priority I/O)
# ---------------------------------------------------------------------------
if [ "$MODE" = audit ]; then
  [ "$(id -u)" -ne 0 ] && info "Not running as root: results will be incomplete."
  NICE=(nice -n 19); command -v ionice >/dev/null 2>&1 && NICE+=(ionice -c3)
  MIN=$((AUDIT_HOURS*60)); FINDINGS=0
  flag() { err "$*"; FINDINGS=$((FINDINGS+1)); }
  info "php-fix $VERSION audit, last ${AUDIT_HOURS}h (read-only, heuristic: findings need human review)"
  command -v ps >/dev/null 2>&1 || err "ps not found (install procps): process checks are SKIPPED"
  command -v ss >/dev/null 2>&1 || info "ss not found (install iproute2): network check skipped"

  WEBROOTS=()
  for r in /var/www /srv/www /srv/http /home /www/wwwroot /usr/share/nginx/html /usr/local/lsws/Example/html; do
    [ -d "$r" ] && WEBROOTS+=("$r")
  done

  # 1) Recently changed PHP / per-dir config in web roots (CMS updates are normal noise)
  if [ ${#WEBROOTS[@]} -gt 0 ]; then
    mapfile -t RECENT < <("${NICE[@]}" find "${WEBROOTS[@]}" -xdev -type f \
      \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '.user.ini' -o -name '.htaccess' \) \
      -mmin "-$MIN" 2>/dev/null)
    info "Changed PHP/.htaccess/.user.ini files in web roots: ${#RECENT[@]} (first 20 below, review if unexpected)"
    for f in ${RECENT[@]+"${RECENT[@]:0:20}"}; do printf '     %s\n' "$(clean "$f")"; done

    # 2) Webshell-like patterns in those files
    if [ ${#RECENT[@]} -gt 0 ]; then
      while read -r f; do [ -n "$f" ] && flag "Webshell-like code: $f"; done < <(printf '%s\0' "${RECENT[@]}" \
        | "${NICE[@]}" xargs -0 grep -lEs \
          'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(POST|GET|REQUEST|COOKIE))|(system|shell_exec|passthru|popen|proc_open|assert|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE|SERVER)' \
        | head -50)
    fi

    # 3) Per-dir config turning upload progress back on
    while read -r f; do [ -n "$f" ] && flag "Re-enables upload progress: $f"; done < <("${NICE[@]}" find "${WEBROOTS[@]}" -xdev -type f \
      \( -name '.htaccess' -o -name '.user.ini' \) -print0 2>/dev/null \
      | xargs -0 -r grep -Eils "${DIRECTIVE//./\\.}[[:space:]=]+\"?(on|1|true|yes)" | head -50)
  fi

  # 4) Shells / interpreters spawned by PHP or the web server
  while read -r pid comm parent; do
    flag "Process $pid ($comm) spawned by $parent: $(ps -o args= -p "$pid" 2>/dev/null | cut -c1-150)"
  done < <(ps -eo pid=,ppid=,comm= 2>/dev/null | awk '
    { pid[NR]=$1; ppid[NR]=$2; comm[NR]=$3; name[$1]=$3 }
    END { for (i=1;i<=NR;i++)
            if (comm[i] ~ /^(sh|bash|dash|zsh|ksh|nc|ncat|netcat|socat|python[0-9.]*|perl|ruby|telnet|curl|wget)$/ &&
                name[ppid[i]] ~ /(php|apache|httpd|lsphp|litespeed|lshttpd)/)
              print pid[i], comm[i], name[ppid[i]] }')

  # 5) Session files that captured upload-progress data (the vulnerable code path was exercised)
  SESS_DIRS=(/var/lib/php/sessions /var/lib/php/session /var/cpanel/php/sessions /tmp)
  while IFS='|' read -r b sapi ver v; do
    p="$("$b" -r 'echo ini_get("session.save_path");' 2>/dev/null)"; p="${p##*;}"
    [ -n "$p" ] && SESS_DIRS+=("$p")
  done < <(collect_bins | grep '|cli|')
  for d in $(printf '%s\n' "${SESS_DIRS[@]}" /var/cpanel/php/sessions/* /opt/alt/php*/var/lib/php/session | sort -u); do
    [ -d "$d" ] || continue
    c="$("${NICE[@]}" find "$d" -maxdepth 1 -type f -name 'sess_*' -mmin "-$MIN" -print0 2>/dev/null \
      | xargs -0 -r grep -ls 'upload_progress_' 2>/dev/null | wc -l)"
    [ "$c" -gt 0 ] && flag "$c recent session file(s) with upload_progress_ data in $d (feature was used; legit progress bars or probing)"
  done

  # 6) Recently changed cron jobs (common persistence)
  while read -r f; do [ -n "$f" ] && flag "Cron changed recently: $f"; done < <(find /etc/crontab /etc/cron.d /etc/cron.hourly \
    /etc/cron.daily /var/spool/cron -xdev -type f -mmin "-$MIN" 2>/dev/null)

  # 7) Busiest POST clients to .php in current access logs (context only, not a finding)
  LOGS=()
  for l in /var/log/apache2/*access*.log /var/log/httpd/*access_log /var/log/nginx/*access*.log \
           /usr/local/apache/domlogs/*/* /var/www/vhosts/*/logs/access*log /usr/local/lsws/logs/access.log \
           /www/wwwlogs/*.log; do
    case "$l" in *.gz|*.bz2|*.xz|*.zip) continue ;; esac
    [ -f "$l" ] && LOGS+=("$l")
  done
  if [ ${#LOGS[@]} -gt 0 ]; then
    info "Top POST-to-.php clients in current access logs (last 200k lines per file, context only):"
    for l in "${LOGS[@]}"; do "${NICE[@]}" tail -n 200000 "$l" 2>/dev/null; done \
      | awk '$6 ~ /"POST/ && $7 ~ /\.php/ {print $1}' | tr -d '\000-\011\013-\037\177' | sort | uniq -c | sort -rn | head -10 | sed 's/^/     /'
    # Only when Content-Type is logged (see --waf-print, "Logging")
    MP="$(for l in "${LOGS[@]}"; do "${NICE[@]}" tail -n 200000 "$l" 2>/dev/null; done | grep -i 'ct="multipart' | tr -d '\000-\011\013-\037\177')"
    if [ -n "$MP" ]; then
      info "Top multipart senders (Content-Type is logged):"
      printf '%s\n' "$MP" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | sed 's/^/     /'
      c5="$(printf '%s\n' "$MP" | awk '$9 ~ /^50[0-4]$/' | wc -l)"
      [ "$c5" -gt 0 ] && flag "$c5 multipart request(s) answered with 500-504 (worker crashes under multipart = exploitation attempts?)"
    fi
  fi

  # 8) PHP worker crashes: memory-corruption exploits usually crash workers while they are being tuned
  CRASH_RE='exited on signal (6|7|11)|SIGSEGV|SIGBUS|Segmentation fault|exit signal Aborted'
  for l in /var/log/php*-fpm.log /var/log/php-fpm/*log /opt/cpanel/ea-php*/root/usr/var/log/php-fpm.log \
           /opt/remi/php*/root/var/log/php-fpm/*log /opt/plesk/php/*/var/log/php-fpm.log \
           /www/server/php/*/var/log/php-fpm.log /var/log/apache2/error*.log /var/log/httpd/error_log \
           /usr/local/apache/logs/error_log /usr/local/lsws/logs/error.log; do
    [ -f "$l" ] || continue
    c="$("${NICE[@]}" tail -n 200000 "$l" 2>/dev/null | grep -Eic "$CRASH_RE")"
    [ "$c" -gt 0 ] && flag "$c PHP/web worker crash line(s) in $l (check timestamps; repeated crashes = exploitation attempts?)"
  done
  if command -v journalctl >/dev/null 2>&1; then
    kc="$(journalctl -k --since "${AUDIT_HOURS} hours ago" --no-pager 2>/dev/null | grep -Ec 'segfault at .*(php|lsphp|httpd|apache2)')"
  else
    kc="$(dmesg 2>/dev/null | grep -Ec 'segfault at .*(php|lsphp|httpd|apache2)')"
  fi
  [ "${kc:-0}" -gt 0 ] && flag "$kc kernel segfault record(s) for PHP / web server processes"

  # 9) PHP dropped into temp directories (write-execute-delete droppers)
  while read -r f; do [ -n "$f" ] && flag "PHP file in a temp directory: $f"; done < <(find /tmp /var/tmp /dev/shm -maxdepth 3 -type f \
    \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \) -mmin "-$MIN" 2>/dev/null | head -20)

  # 10) Reverse-shell patterns in any running command line
  while read -r pid user args; do
    flag "Reverse-shell-like process $pid ($user): ${args:0:150}"
  done < <(ps -eo pid=,user=,args= 2>/dev/null | grep -E '/dev/(tcp|udp)/|mkfifo .*(nc|sh)|\bnc(at)? .*-[ec] |(ba)?sh -i|socat .*exec|fsockopen|pty\.spawn' \
             | grep -v -e 'grep -E')

  # 11) Shells / interpreters running as a web user and detached from their parent (double-forked)
  while read -r pid user comm; do
    flag "Detached $comm running as $user (pid $pid): $(ps -o args= -p "$pid" 2>/dev/null | cut -c1-150)"
  done < <(ps -eo pid=,ppid=,user=,comm= 2>/dev/null | awk '
    $2 == 1 && $3 ~ /^(www-data|apache|nginx|nobody|http|httpd|wwwrun|lsadm)$/ &&
    $4 ~ /^(sh|bash|dash|zsh|ksh|nc|ncat|netcat|socat|python[0-9.]*|perl|ruby|php)$/ { print $1, $3, $4 }')

  # 12) Network connections owned by shells / interpreters
  if command -v ss >/dev/null 2>&1; then
    while read -r line; do [ -n "$line" ] && flag "Shell/interpreter with a network connection: ${line:0:200}"; done < <(ss -tnpH state established 2>/dev/null \
      | grep -E 'users:\(\("(sh|bash|dash|nc|ncat|netcat|socat|perl|python[0-9.]*|ruby)"')
  fi

  # 13) PHP containers: this script does not reach inside them
  if command -v docker >/dev/null 2>&1; then
    while read -r line; do [ -n "$line" ] && err "PHP container not covered (patch / rebuild its image): $line"; done \
      < <(docker ps --format '{{.Names}} ({{.Image}})' 2>/dev/null | grep -i php)
  fi

  echo
  if [ "$FINDINGS" -gt 0 ]; then err "$FINDINGS item(s) to review. Heuristic: confirm before acting."; exit 3; fi
  ok "Nothing suspicious found by these heuristics (that is not proof of a clean system)."
  exit 0
fi

# ---------------------------------------------------------------------------
# --revert: restore the backups of one run
# ---------------------------------------------------------------------------
if [ "$MODE" = revert ]; then
  BAK_RE='\.bak-[0-9]{8}-[0-9]{6}$'
  if [ -z "$REVERT_TS" ]; then
    REVERT_TS="$(find ${existing_roots[@]+"${existing_roots[@]}"} -xdev -type f -name '*.bak-*' 2>/dev/null \
      | grep -E "$BAK_RE" | grep -oE '[0-9]{8}-[0-9]{6}$' | sort -u | tail -1)"
  fi
  [ -n "$REVERT_TS" ] || { err "No php-fix backups found."; exit 1; }
  info "Reverting run $REVERT_TS"
  mapfile -t BAKS < <(find ${existing_roots[@]+"${existing_roots[@]}"} -xdev -type f -name "*.bak-$REVERT_TS" 2>/dev/null | sort)
  for f in ${BAKS[@]+"${BAKS[@]}"}; do
    orig="${f%.bak-$REVERT_TS}"
    if [ "$DRY_RUN" -eq 1 ]; then info "[dry-run] Would restore: $orig"; continue; fi
    dir_safe "$orig" || { FAILED=$((FAILED+1)); continue; }
    [ -L "$orig" ] && { err "Refusing to write through symlink: $orig"; FAILED=$((FAILED+1)); continue; }
    cp -p --no-dereference "$f" "$orig" && { ok "Restored: $orig"; CHANGED=$((CHANGED+1)); } \
      || { err "Could not restore: $orig"; FAILED=$((FAILED+1)); }
  done
  for c in "${MODPHP_CONFS[@]}"; do
    [ -f "$c" ] && grep -q '^# php-fix:' "$c" || continue
    if [ "$DRY_RUN" -eq 1 ]; then info "[dry-run] Would remove: $c"; continue; fi
    case "$c" in /etc/apache2/conf-available/*) command -v a2disconf >/dev/null && a2disconf -q zz-php2shell >/dev/null 2>&1 ;; esac
    rm -f "$c" && { ok "Removed: $c"; CHANGED=$((CHANGED+1)); }
  done
  reload_services
  echo
  echo "Restored/removed: $CHANGED | Errors: $FAILED   (backup files were kept)"
  [ "$FAILED" -eq 0 ] || exit 1
  exit 0
fi

# ---------------------------------------------------------------------------
# default: apply the mitigation
# ---------------------------------------------------------------------------

# 1) Collect php.ini files
mapfile -t INI_FILES < <(
  {
    [ ${#existing_roots[@]} -gt 0 ] && find "${existing_roots[@]}" -xdev -type f -name 'php.ini' 2>/dev/null
    command -v php >/dev/null 2>&1 && php --ini 2>/dev/null | awk -F': *' '/Loaded Configuration File/ {print $2}'
  } | grep -v '(none)' | while read -r f; do [ -f "$f" ] && readlink -f "$f"; done | sort -u
)

if [ ${#INI_FILES[@]} -eq 0 ]; then
  err "No php.ini found."
  exit 1
fi

info "Found ${#INI_FILES[@]} php.ini file(s)."

for f in "${INI_FILES[@]}"; do
  active_lines="$(grep -Ei "$ACTIVE_RE" "$f" || true)"
  if [ -n "$active_lines" ] && ! echo "$active_lines" | grep -Eivq "$OFF_RE"; then
    ok "Already Off: $f"; SKIPPED=$((SKIPPED+1)); continue
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    info "[dry-run] Would change: $f"; continue
  fi

  backup "$f" || { err "Backup failed: $f"; FAILED=$((FAILED+1)); continue; }

  if grep -Eiq "$ANY_RE" "$f"; then
    # Replace existing (commented or active) line
    sed -i -E "s/${ANY_RE}.*/${DIRECTIVE} = Off/I" "$f"
  elif grep -q '^\[Session\]' "$f"; then
    # Insert right below the [Session] section header
    sed -i "/^\[Session\]/a ${DIRECTIVE} = Off" "$f"
  else
    printf '\n[Session]\n%s = Off\n' "$DIRECTIVE" >> "$f"
  fi

  if grep -Eiq "$OFF_RE" "$f"; then
    ok "Updated: $f  (backup: $f.bak-$TS)"; CHANGED=$((CHANGED+1))
  else
    err "Could not update: $f"; FAILED=$((FAILED+1))
  fi
done

if [ ${#existing_roots[@]} -gt 0 ]; then
  # 2) Extra .ini files (conf.d etc.) that turn it back On
  mapfile -t EXTRA_INI < <(find "${existing_roots[@]}" -xdev -type f -name '*.ini' ! -name 'php.ini' -print0 2>/dev/null \
    | xargs -0 -r grep -Eil "$ACTIVE_RE" 2>/dev/null | sort -u)
  for f in ${EXTRA_INI[@]+"${EXTRA_INI[@]}"}; do
    if ! grep -Ei "$ACTIVE_RE" "$f" | grep -Eivq "$OFF_RE"; then continue; fi
    if [ "$DRY_RUN" -eq 1 ]; then info "[dry-run] Would fix override: $f"; continue; fi
    backup "$f" && sed -i -E "s/${ACTIVE_RE}.*/${DIRECTIVE} = Off/I" "$f" \
      && { ok "Fixed override: $f  (backup: $f.bak-$TS)"; CHANGED=$((CHANGED+1)); } \
      || { err "Could not fix override: $f"; FAILED=$((FAILED+1)); }
  done

  # 3) PHP-FPM pool php_value/php_flag overrides -> force php_admin_flag off
  mapfile -t POOL_FILES < <(find "${existing_roots[@]}" -xdev -type f -name '*.conf' -print0 2>/dev/null \
    | xargs -0 -r grep -El "^[[:space:]]*${POOL_RE}" 2>/dev/null | sort -u)
  for f in ${POOL_FILES[@]+"${POOL_FILES[@]}"}; do
    if ! grep -E "^[[:space:]]*${POOL_RE}" "$f" | grep -Eivq "$POOL_OFF_RE" \
       && ! grep -Eq "^[[:space:]]*php_(value|flag)\[${DIRECTIVE//./\\.}\]" "$f"; then
      continue  # already php_admin_flag ... = off
    fi
    if [ "$DRY_RUN" -eq 1 ]; then info "[dry-run] Would fix FPM pool: $f"; continue; fi
    backup "$f" && sed -i -E "s/^([[:space:]]*)(${POOL_RE})[[:space:]]*=.*/\1php_admin_flag[${DIRECTIVE}] = off/" "$f" \
      && { ok "Fixed FPM pool: $f  (backup: $f.bak-$TS)"; CHANGED=$((CHANGED+1)); } \
      || { err "Could not fix FPM pool: $f"; FAILED=$((FAILED+1)); }
  done

  # 3b) Pools with no setting at all: add php_admin_flag, otherwise a .user.ini (or a pool
  #     php_value added later) can turn it back on over php.ini. Guarded by `php-fpm -t`.
  mapfile -t BARE_POOLS < <(find "${existing_roots[@]}" -xdev -type f -name '*.conf' -print0 2>/dev/null \
    | xargs -0 -r grep -lE '^[[:space:]]*listen[[:space:]]*=' 2>/dev/null \
    | xargs -d '\n' -r grep -lE '^[[:space:]]*pm[[:space:]]*=' 2>/dev/null \
    | xargs -d '\n' -r grep -lE '^[[:space:]]*\[[^]]+\][[:space:]]*$' 2>/dev/null \
    | xargs -d '\n' -r grep -LE "^[[:space:]]*${POOL_RE}" 2>/dev/null | sort -u)
  if [ ${#BARE_POOLS[@]} -gt 0 ]; then
    FPM_OK_BEFORE=()
    while read -r b; do [ -n "$b" ] && "$b" -t >/dev/null 2>&1 && FPM_OK_BEFORE+=("$b"); done < <(find_fpm_bins)
    HARDENED=()
    for f in "${BARE_POOLS[@]}"; do
      if [ "$DRY_RUN" -eq 1 ]; then info "[dry-run] Would add php_admin_flag to FPM pool(s) in: $f"; continue; fi
      tmp="$(mktemp)"
      # after every [pool] header except [global]
      awk -v line="php_admin_flag[${DIRECTIVE}] = off" \
        '{ print } /^[[:space:]]*\[[^]]+\][[:space:]]*$/ && !/^[[:space:]]*\[global\]/ { print line }' "$f" > "$tmp"
      grep -qF "php_admin_flag[${DIRECTIVE}]" "$tmp" || { rm -f "$tmp"; continue; }   # only [global] here
      backup "$f" || { err "Backup failed: $f"; FAILED=$((FAILED+1)); rm -f "$tmp"; continue; }
      cat "$tmp" > "$f" && HARDENED+=("$f") \
        && ok "Locked FPM pool(s) with php_admin_flag: $f  (backup: $f.bak-$TS)" \
        || { err "Could not lock FPM pool: $f"; FAILED=$((FAILED+1)); }
      rm -f "$tmp"
    done
    for b in ${FPM_OK_BEFORE[@]+"${FPM_OK_BEFORE[@]}"}; do
      [ ${#HARDENED[@]} -gt 0 ] || break
      if ! "$b" -t >/dev/null 2>&1; then
        err "$b -t fails after locking pools: restoring them, FPM config left as it was"
        for f in "${HARDENED[@]}"; do cp -p "$f.bak-$TS" "$f"; done
        FAILED=$((FAILED+1)); HARDENED=(); break
      fi
    done
    CHANGED=$((CHANGED+${#HARDENED[@]}))
  fi
fi

# 4) mod_php: global php_admin_flag so .htaccess cannot turn it back on
MODPHP_CONF=""
if [ -n "$APACHECTL" ] && { "$APACHECTL" -M 2>/dev/null | grep -Eiq '^[[:space:]]*php[0-9]*_module' \
     || ls /etc/apache2/mods-enabled/php*.load >/dev/null 2>&1; }; then
  if [ -d /etc/apache2/conf-available ] && command -v a2enconf >/dev/null 2>&1; then
    MODPHP_CONF="${MODPHP_CONFS[0]}"     # Debian / Ubuntu
  elif [ -d /etc/httpd/conf.d ]; then
    MODPHP_CONF="${MODPHP_CONFS[1]}"     # RHEL family
  elif [ -d /etc/apache2/conf.d ]; then
    MODPHP_CONF="${MODPHP_CONFS[2]}"     # cPanel EA4
  else
    err "mod_php detected but no Apache conf.d directory found; add php_admin_flag ${DIRECTIVE} off manually"
  fi
fi
if [ -n "$MODPHP_CONF" ]; then
  MODPHP_BODY="# php-fix: php2shell (CVE-2026-109618 / CVE-2026-109619) mitigation
# php_admin_flag cannot be overridden from .htaccess
<IfModule php_module>
    php_admin_flag ${DIRECTIVE} off
</IfModule>
<IfModule php7_module>
    php_admin_flag ${DIRECTIVE} off
</IfModule>
<IfModule php5_module>
    php_admin_flag ${DIRECTIVE} off
</IfModule>"
  if [ -f "$MODPHP_CONF" ] && [ "$(cat "$MODPHP_CONF")" = "$MODPHP_BODY" ]; then
    ok "mod_php admin flag already present: $MODPHP_CONF"
  elif [ "$DRY_RUN" -eq 1 ]; then
    info "[dry-run] Would write mod_php admin flag: $MODPHP_CONF"
  elif ! "$APACHECTL" -t >/dev/null 2>&1; then
    err "Apache config test already fails before any change; not touching Apache"; FAILED=$((FAILED+1))
  elif [ -L "$MODPHP_CONF" ] || ! dir_safe "$MODPHP_CONF"; then
    err "Refusing to write: $MODPHP_CONF"; FAILED=$((FAILED+1))
  else
    printf '%s\n' "$MODPHP_BODY" > "$MODPHP_CONF"
    case "$MODPHP_CONF" in /etc/apache2/conf-available/*) a2enconf -q zz-php2shell >/dev/null 2>&1 ;; esac
    if "$APACHECTL" -t >/dev/null 2>&1; then
      ok "Wrote mod_php admin flag: $MODPHP_CONF"; CHANGED=$((CHANGED+1))
    else
      case "$MODPHP_CONF" in /etc/apache2/conf-available/*) a2disconf -q zz-php2shell >/dev/null 2>&1 ;; esac
      rm -f "$MODPHP_CONF"
      err "Apache config test failed with $MODPHP_CONF, removed it again"; FAILED=$((FAILED+1))
    fi
  fi
fi

# 5) Reload services
reload_services

# 6) Verify via CLI and FPM binaries (each loads its own php.ini)
LEGACY=0; EOL=0
# check_result <binary> <sapi> <PHP_VERSION> <effective value>
check_result() {
  local b="$1" sapi="$2" ver="$3" v="$4" n
  n="$(branch_num "$ver")"
  [ -n "$n" ] || { err "$b: could not read PHP version"; FAILED=$((FAILED+1)); return; }
  if [ "$n" -lt 504 ]; then
    err "$b ($sapi $ver): NOT PROTECTED. ${DIRECTIVE} does not exist before PHP 5.4, but the multipart parser is still exposed."
    err "    Upgrade PHP, or block multipart/form-data POSTs at the proxy/WAF (see --waf-print)."
    LEGACY=1; return
  fi
  if is_off "$v"; then ok "$b ($sapi $ver): Off"
  else err "$b ($sapi $ver): STILL ON ($v)"; FAILED=$((FAILED+1)); fi
  if [ "$n" -lt 802 ]; then
    err "    EOL branch: an official patch is unlikely. Block/limit multipart POSTs at the proxy/WAF (see --waf-print) and plan an upgrade."
    EOL=1
  fi
}

info "Verification:"
while IFS='|' read -r b sapi ver v; do
  check_result "$b" "$sapi" "$ver" "$v"
done < <(collect_bins)

# What each running FPM pool really serves (php.ini + pool overrides), over FastCGI
if [ "$DRY_RUN" -eq 1 ] || { [ "$NO_RESTART" -eq 1 ] && [ "$CHANGED" -gt 0 ]; }; then
  [ -n "$(find_fpm_bins)" ] && info "Running FPM pools not queried (dry run / not reloaded yet). Check them later with --check."
else
  [ "$CHANGED" -gt 0 ] && sleep 2   # let the graceful reload finish
  while IFS='|' read -r pool addr ver v; do
    if [ "$ver" = ERR ]; then info "FPM pool $pool ($addr): not verified, $v"; continue; fi
    if is_off "$v"; then ok "FPM pool $pool ($addr, PHP $ver): Off (live)"
    else err "FPM pool $pool ($addr, PHP $ver): STILL ON (live, $v)"; FAILED=$((FAILED+1)); fi
  done < <(fcgi_pools)
fi

echo
echo "Changed: $CHANGED | Already Off: $SKIPPED | Errors: $FAILED"
if [ "$DRY_RUN" -eq 1 ]; then
  info "Dry run finished, nothing was changed."
  [ "$LEGACY" -eq 1 ] && exit 2
  exit 0
fi
if [ "$FAILED" -gt 0 ]; then
  err "Some steps failed, check the output above."
  exit 1
fi
if [ "$LEGACY" -eq 1 ]; then
  err "PHP < 5.4 found: this mitigation does NOT protect it. See the warnings above."
  exit 2
fi
echo -e "${G}DONE ✔ ${DIRECTIVE} = Off${N}"
[ "$EOL" -eq 1 ] && err "EOL PHP versions found: they will likely get no patch. See the warnings above."
echo "Next: run with --check after patching, and --audit to look for signs of compromise."
echo "Reminder: this is a stopgap. Upgrade PHP to the patched release as soon as possible."
