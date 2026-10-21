#!/usr/bin/env bash
# php-fix: emergency mitigation for php2shell (CVE-2026-109618 / CVE-2026-109619)
# Sets session.upload_progress.enabled = Off in every PHP install on the host.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ersinkoc/php-fix/main/install.sh | sudo bash
#   curl -fsSL .../install.sh | sudo bash -s -- --dry-run      # show what would change, change nothing
#   curl -fsSL .../install.sh | sudo bash -s -- --no-restart   # do not reload PHP / web services
#
# This is a stopgap. The real fix is upgrading PHP to the patched release.

set -u

DIRECTIVE="session.upload_progress.enabled"
TS="$(date +%Y%m%d-%H%M%S)"
DRY_RUN=0
NO_RESTART=0

for arg in "$@"; do
  case "$arg" in
    --dry-run)    DRY_RUN=1 ;;
    --no-restart) NO_RESTART=1 ;;
    -h|--help)    echo "Usage: install.sh [--dry-run] [--no-restart]"; exit 0 ;;
    *) echo "Unknown option: $arg"; exit 1 ;;
  esac
done

if [ -t 1 ]; then G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'; else G=''; Y=''; R=''; N=''; fi
ok()   { echo -e "${G}[OK]${N} $*"; }
info() { echo -e "${Y}[..]${N} $*"; }
err()  { echo -e "${R}[!!]${N} $*"; }

if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
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

CHANGED=0; SKIPPED=0; FAILED=0

# Refuse to touch files in directories a non-root user could write to (symlink planting),
# and never write the backup through an existing file or symlink.
backup() {
  local dir dst="$1.bak-$TS"
  dir="$(dirname "$1")"
  if [ "$(stat -c %u "$dir" 2>/dev/null)" != "0" ] || [ -n "$(find "$dir" -maxdepth 0 -perm /022 2>/dev/null)" ]; then
    err "Unsafe directory (not root-owned or group/world-writable), skipping: $dir"; return 1
  fi
  if [ -e "$dst" ] || [ -L "$dst" ]; then err "Backup path already exists: $dst"; return 1; fi
  cp -p --no-dereference "$1" "$dst"
}

# Expands to the array contents, or nothing if empty (safe under `set -u` on bash < 4.4, e.g. CentOS 7)
# usage: for x in ${ARR[@]+"${ARR[@]}"}; do ...

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
  mapfile -t EXTRA_INI < <(find "${existing_roots[@]}" -xdev -type f -name '*.ini' ! -name 'php.ini' 2>/dev/null \
    | xargs -r grep -Eil "$ACTIVE_RE" 2>/dev/null | sort -u)
  for f in ${EXTRA_INI[@]+"${EXTRA_INI[@]}"}; do
    if ! grep -Ei "$ACTIVE_RE" "$f" | grep -Eivq "$OFF_RE"; then continue; fi
    if [ "$DRY_RUN" -eq 1 ]; then info "[dry-run] Would fix override: $f"; continue; fi
    backup "$f" && sed -i -E "s/${ACTIVE_RE}.*/${DIRECTIVE} = Off/I" "$f" \
      && { ok "Fixed override: $f  (backup: $f.bak-$TS)"; CHANGED=$((CHANGED+1)); } \
      || { err "Could not fix override: $f"; FAILED=$((FAILED+1)); }
  done

  # 3) PHP-FPM pool php_value/php_flag overrides -> force php_admin_flag off
  mapfile -t POOL_FILES < <(find "${existing_roots[@]}" -xdev -type f -name '*.conf' 2>/dev/null \
    | xargs -r grep -El "^[[:space:]]*${POOL_RE}" 2>/dev/null | sort -u)
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
fi

# 4) Reload services
if [ "$DRY_RUN" -eq 0 ] && [ "$NO_RESTART" -eq 0 ] && [ "$CHANGED" -gt 0 ]; then
  info "Reloading PHP / web services..."
  if command -v systemctl >/dev/null 2>&1; then
    mapfile -t SVCS < <(systemctl list-units --type=service --no-legend 2>/dev/null \
      | awk '{for(i=1;i<=NF;i++) if($i ~ /\.service$/){print $i;break}}' \
      | grep -Ei '^(php.*fpm|ea-php.*|plesk-php.*|apache2|httpd|lsws|lshttpd|litespeed)\.service$')
    for s in ${SVCS[@]+"${SVCS[@]}"}; do
      systemctl reload-or-restart "$s" && ok "Reloaded: $s" || err "Could not reload: $s"
    done
  else
    for s in php-fpm php7.4-fpm php8.0-fpm php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm php8.5-fpm apache2 httpd; do
      service "$s" reload >/dev/null 2>&1 && ok "Reloaded: $s"
    done
  fi
  pkill -f lsphp >/dev/null 2>&1 && ok "Killed lsphp processes (LiteSpeed will respawn them)"
fi

# 5) Verify via CLI binaries
info "Verification:"
mapfile -t PHP_BINS < <(
  {
    command -v php 2>/dev/null
    ls /usr/bin/php[0-9]* /opt/cpanel/ea-php*/root/usr/bin/php /opt/alt/php*/usr/bin/php \
       /opt/plesk/php/*/bin/php /www/server/php/*/bin/php /usr/local/php*/bin/php \
       /opt/remi/php*/root/usr/bin/php /usr/local/lsws/lsphp*/bin/php 2>/dev/null
  } | while read -r b; do [ -x "$b" ] && readlink -f "$b"; done | sort -u
)
for b in ${PHP_BINS[@]+"${PHP_BINS[@]}"}; do
  ver="$("$b" -r 'echo PHP_VERSION;' 2>/dev/null)" || continue
  v="$("$b" -r "echo ini_get('${DIRECTIVE}');" 2>/dev/null)"
  if [ -z "$v" ] || [ "$v" = "0" ]; then ok "$b ($ver): Off"
  else err "$b ($ver): STILL ON ($v)"; FAILED=$((FAILED+1)); fi
done

echo
echo "Changed: $CHANGED | Already Off: $SKIPPED | Errors: $FAILED"
if [ "$DRY_RUN" -eq 1 ]; then
  info "Dry run finished, nothing was changed."
elif [ "$FAILED" -eq 0 ]; then
  echo -e "${G}DONE ✔ ${DIRECTIVE} = Off${N}"
  echo "Reminder: this is a stopgap. Upgrade PHP to the patched release as soon as possible."
else
  err "Some steps failed, check the output above."
  exit 1
fi
