#!/usr/bin/env bash
# End-to-end tests for install.sh. Runs as root inside a throwaway container:
#   docker run --rm -v "$PWD:/src:ro" debian:trixie bash /src/tests/run.sh
# Installs PHP with the distro package manager, then exercises every mode.

set -u
S=/src/install.sh
PASS=0; FAIL=0
pass() { echo "PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $*"; FAIL=$((FAIL+1)); }
same() { [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]; }
# apachectl start/stop return before the server is really up/down: wait on the port
a_start() { apache2ctl start >/dev/null 2>&1; for _ in $(seq 50); do curl -s -o /dev/null localhost/ && return; sleep 0.2; done; }
a_stop()  { apache2ctl stop >/dev/null 2>&1; for _ in $(seq 50); do curl -s -o /dev/null localhost/ || return; sleep 0.2; done; }
expect_rc() { local want="$1" got="$2" what="$3"; [ "$got" = "$want" ] && pass "$what (rc=$got)" || fail "$what (rc=$got, want $want)"; }

echo "== Installing PHP"
if command -v apt-get >/dev/null; then
  apt-get update -qq >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq php-cli php-fpm apache2 libapache2-mod-php nginx curl >/dev/null 2>&1
  INI_DIR="$(ls -d /etc/php/*/ | head -1)"
  CLI_INI="${INI_DIR}cli/php.ini"; POOL="${INI_DIR}fpm/pool.d/www.conf"; CONFD="${INI_DIR}cli/conf.d"
  POOL2="${INI_DIR}fpm/pool.d/second.conf"; WEBUSER=www-data; SOCK2=/run/php/second.sock
  MODPHP=1
elif command -v dnf >/dev/null; then
  dnf install -y -q php-cli php-fpm httpd procps-ng iproute >/dev/null 2>&1
  CLI_INI=/etc/php.ini; POOL=/etc/php-fpm.d/www.conf; CONFD=/etc/php.d
  POOL2=/etc/php-fpm.d/second.conf; WEBUSER=apache; SOCK2=/run/php-fpm/second.sock
  MODPHP=0
else
  echo "unsupported image"; exit 1
fi
command -v php >/dev/null || { echo "PHP install failed"; exit 1; }
echo "PHP $(php -r 'echo PHP_VERSION;')"

# Overrides the script must catch
echo "php_value[session.upload_progress.enabled] = 1" >> "$POOL"
echo "session.upload_progress.enabled=On" > "$CONFD/99-test-on.ini"
# A pool with no setting at all: must get php_admin_flag added
printf '[second]
user = %s
group = %s
listen = %s
listen.owner = %s
listen.group = %s
pm = ondemand
pm.max_children = 2
'   "$WEBUSER" "$WEBUSER" "$SOCK2" "$WEBUSER" "$WEBUSER" > "$POOL2"
# Not an FPM pool (dovecot-style "listen ="): must not be touched
printf '[section]
listen = *
' > /etc/decoy-test.conf; cp -p /etc/decoy-test.conf /root/decoy.orig
FPMBIN="$(ls /usr/sbin/php-fpm* | head -1)"
cp -p "$CLI_INI" /root/cli.ini.orig

echo "== --waf-print"
out="$(bash $S --waf-print)"; expect_rc 0 $? "waf-print"
echo "$out" | grep -q 'SecRule ARGS_NAMES' && pass "waf-print has ModSecurity rule" || fail "waf-print content"

echo "== --dry-run changes nothing"
bash $S --dry-run >/dev/null; expect_rc 0 $? "dry-run"
same "$CLI_INI" /root/cli.ini.orig && pass "dry-run left php.ini alone" || fail "dry-run modified php.ini"
ls /etc/apache2/conf-available/zz-php2shell.conf >/dev/null 2>&1 && fail "dry-run wrote mod_php conf" || pass "dry-run wrote no mod_php conf"

echo "== fix"
bash $S; expect_rc 0 $? "fix"
[ "$(php -r 'echo ini_get("session.upload_progress.enabled");')" = "" ] || [ "$(php -r 'echo ini_get("session.upload_progress.enabled");')" = "0" ] \
  && pass "CLI effective value Off" || fail "CLI still On"
grep -q '^php_admin_flag\[session.upload_progress.enabled\] = off' "$POOL" && pass "pool hardened" || fail "pool not hardened"
grep -qi 'session.upload_progress.enabled = Off' "$CONFD/99-test-on.ini" && pass "conf.d override fixed" || fail "conf.d override"
ls "$CLI_INI".bak-* >/dev/null 2>&1 && pass "backup created" || fail "no backup"
grep -q '^php_admin_flag\[session.upload_progress.enabled\] = off' "$POOL2" && pass "bare pool locked with php_admin_flag" || fail "bare pool not locked"
"$FPMBIN" -t >/dev/null 2>&1 && pass "php-fpm -t passes after locking" || fail "php-fpm -t fails"
same /etc/decoy-test.conf /root/decoy.orig && pass "non-FPM 'listen =' config untouched" || fail "decoy config modified"

echo "== idempotent"
bash $S | grep -q '^Changed: 0 ' && pass "second run changes nothing" || fail "second run changed something"

if [ "$MODPHP" = 1 ]; then
  echo "== mod_php vs .htaccess"
  apache2ctl -t >/dev/null 2>&1 && pass "apache config valid" || fail "apache config broken"
  sed -i "/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/" /etc/apache2/apache2.conf
  echo '<?php var_export(ini_get("session.upload_progress.enabled"));' > /var/www/html/t.php
  echo 'php_flag session.upload_progress.enabled on' > /var/www/html/.htaccess
  a_start
  r="$(curl -s localhost/t.php)"
  [ "$r" = "'0'" ] && pass ".htaccess cannot re-enable (got $r)" || fail ".htaccess re-enabled it (got $r)"
  a_stop

  echo "== --waf-print Apache rule, server-wide"
  W=/etc/apache2/conf-enabled/zz-php2shell-waf.conf
  bash $S --waf-print | sed -n '/^<Location "\/">/,/^<\/Location>/p' > "$W"
  grep -q 'Require all denied' "$W" && pass "extracted server-wide Apache rule" || fail "could not extract Apache rule"
  apache2ctl -t >/dev/null 2>&1 && pass "waf Apache snippet passes configtest" || fail "waf Apache snippet breaks config"
  mkdir -p /var/www/html/sub && cp /var/www/html/t.php /var/www/html/sub/
  a2enmod -q rewrite >/dev/null 2>&1   # the bypass attempts below use mod_rewrite
  printf 'RewriteEngine On\nRewriteRule ^nothing$ - [L]\nRequire all granted\n' > /var/www/html/sub/.htaccess   # bypass attempt
  a_start
  code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
  waf_checks() {   # $1 = base URL
    [ "$(code -F a=b "$1/t.php")" = 403 ] && pass "$2: multipart POST blocked" || fail "$2: multipart POST not blocked"
    [ "$(code -X PUT -F a=b "$1/t.php")" = 403 ] && pass "$2: multipart PUT blocked" || fail "$2: multipart PUT not blocked"
    [ "$(code -H 'Content-Type: MuLtIpArT/form-data; boundary=x' --data-binary x "$1/t.php")" = 403 ]       && pass "$2: mixed-case Content-Type blocked" || fail "$2: mixed-case Content-Type not blocked"
    [ "$(code -F a=b "$1/wp-admin/async-upload.php-evil.php")" = 403 ] && pass "$2: prefix trick blocked" || fail "$2: prefix trick not blocked"
    [ "$(code -F a=b "$1/wp-admin/async-upload.php")" != 403 ] && pass "$2: allowlisted path passes" || fail "$2: allowlisted path blocked"
    [ "$(code -d a=b "$1/t.php")" = 200 ] && pass "$2: urlencoded POST passes" || fail "$2: urlencoded POST blocked"
    [ "$(code -H 'Content-Type: application/json' -d '{}' "$1/t.php")" = 200 ] && pass "$2: JSON POST passes" || fail "$2: JSON POST blocked"
  }
  waf_checks http://localhost apache
  [ "$(code -F a=b localhost/sub/t.php)" = 403 ] && pass "apache: subfolder .htaccess cannot bypass" || fail "apache: subfolder .htaccess bypassed the rule"
  a_stop
  # vhost with its own rewrite rules still inherits the block
  VH=/etc/apache2/sites-enabled/000-default.conf; cp "$VH" /root/vhost.orig
  sed -i 's|</VirtualHost>|    RewriteEngine On\n    RewriteRule ^/nothing$ - [L]\n</VirtualHost>|' "$VH"
  a_start
  [ "$(code -F a=b localhost/t.php)" = 403 ] && pass "apache: vhost with own RewriteEngine still blocked" || fail "apache: vhost rewrite rules dropped the block"
  a_stop
  cp /root/vhost.orig "$VH"
  rm -rf "$W" /var/www/html/sub

  echo "== nginx + FPM: .user.ini cannot re-enable on a locked pool; nginx WAF rule"
  echo 'session.upload_progress.enabled = On' > /var/www/html/.user.ini
  bash $S --waf-print | sed -n '/^map /,/^}/p' > /etc/nginx/conf.d/php2shell.conf
  guard="$(bash $S --waf-print | grep -E '^#   (set|if) ' | sed 's/^#   //')"
  cat > /etc/nginx/sites-enabled/default <<NGX
server {
    listen 8080;
    root /var/www/html;
    $guard
    location ~ \.php\$ { include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_pass unix:$SOCK2; }
}
NGX
  nginx -t >/dev/null 2>&1 && pass "nginx snippet passes nginx -t" || fail "nginx snippet breaks config"
  mkdir -p /run/php /run/php-fpm; "$FPMBIN" -D && nginx
  for _ in $(seq 50); do [ "$(code localhost:8080/t.php)" = 200 ] && break; sleep 0.2; done
  r="$(curl -s localhost:8080/t.php)"
  [ "$r" = "'0'" ] && pass ".user.ini cannot re-enable on locked pool (got $r)" || fail ".user.ini re-enabled it (got $r)"
  waf_checks http://localhost:8080 nginx
  nginx -s stop; pkill -f php-fpm; sleep 1
  rm -f /var/www/html/.user.ini /etc/nginx/conf.d/php2shell.conf
fi

echo "== --check"
bash $S --check; rc=$?
[ "$rc" = 0 ] || [ "$rc" = 1 ] && pass "check runs (rc=$rc)" || fail "check rc=$rc"

echo "== --audit finds a planted webshell"
mkdir -p /var/www/html
# inert webshell-shaped fixture for the audit test (Apache is stopped, file removed right after)
echo '<?php eval(base64_decode($_POST["x"]));' > /var/www/html/shell.php
out="$(bash $S --audit 2>&1)"; rc=$?
expect_rc 3 "$rc" "audit flags findings"
echo "$out" | grep -q 'Webshell-like code: /var/www/html/shell.php' && pass "audit names the webshell" || fail "audit missed webshell"
rm -f /var/www/html/shell.php

echo "== --audit: worker crashes, temp-dir PHP, reverse shell"
echo "WARNING: [pool www] child 4242 exited on signal 11 (SIGSEGV) after 0.5 seconds from start" >> /var/log/phptest-fpm.log
echo '<?php echo 1;' > /tmp/dropper.php
sh -c 'sleep 60; : /dev/tcp/203.0.113.7/4444' & RS=$!
out="$(bash $S --audit 2>&1)"
echo "$out" | grep -q 'worker crash line(s) in /var/log/phptest-fpm.log' && pass "audit flags worker crash" || fail "audit missed worker crash"
echo "$out" | grep -q 'PHP file in a temp directory: /tmp/dropper.php' && pass "audit flags temp-dir PHP" || fail "audit missed temp-dir PHP"
echo "$out" | grep -q 'Reverse-shell-like process' && pass "audit flags reverse-shell command line" || fail "audit missed reverse shell"
kill "$RS" 2>/dev/null; pkill -f '203.0.113.7' 2>/dev/null; rm -f /var/log/phptest-fpm.log /tmp/dropper.php

echo "== --audit output cannot carry terminal escapes"
evil="/var/www/html/$(printf 'x\033[2J\033[1A[OK] clean')"
echo '<?php system($_GET["c"]);' > "$evil"
out="$(bash $S --audit 2>&1)"
printf '%s' "$out" | grep -q "$(printf '\033')\[2J" && fail "escape sequence reached the terminal" || pass "escape sequences stripped"
rm -f "$evil"
for c1 in '\233' '\302\233'; do   # 8-bit CSI and UTF-8 encoded CSI
  evil="/var/www/html/$(printf "y${c1}2J")ü.php"
  echo '<?php system($_GET["c"]);' > "$evil"
  out="$(bash $S --audit 2>&1)"
  printf '%s' "$out" | LC_ALL=C grep -q "$(printf "$c1")" && fail "C1 control ($c1) reached the terminal" || pass "C1 control ($c1) stripped"
  printf '%s' "$out" | grep -q 'ü\.php' && pass "UTF-8 name kept readable" || fail "UTF-8 name mangled"
  rm -f "$evil"
done

echo "== stub binaries: EOL and < 5.4"
printf '#!/bin/sh\ncase "$2" in *PHP_VERSION*) echo 7.4.33;; *) echo;; esac\n' > /usr/bin/php74; chmod +x /usr/bin/php74
bash $S --no-restart | grep -q 'EOL branch' && pass "EOL warning" || fail "no EOL warning"
printf '#!/bin/sh\ncase "$2" in *PHP_VERSION*) echo 5.3.29;; *) echo;; esac\n' > /usr/bin/php53; chmod +x /usr/bin/php53
bash $S --no-restart >/dev/null; expect_rc 2 $? "PHP < 5.4 exits 2"
rm -f /usr/bin/php74 /usr/bin/php53

echo "== --revert"
bash $S --revert; expect_rc 0 $? "revert"
same "$CLI_INI" /root/cli.ini.orig && pass "php.ini restored byte-for-byte" || fail "php.ini not restored"
grep -q 'php_admin_flag' "$POOL2" && fail "locked pool not restored" || pass "locked pool restored"
ls /etc/apache2/conf-available/zz-php2shell.conf /etc/apache2/conf-enabled/zz-php2shell.conf >/dev/null 2>&1 \
  && fail "mod_php conf still present" || pass "mod_php conf removed"
[ "$MODPHP" = 1 ] && { apache2ctl -t >/dev/null 2>&1 && pass "apache config valid after revert" || fail "apache broken after revert"; }

echo "== symlink planting refused"
mkdir -p /srv/evil && chmod 777 /srv/evil && printf '[Session]\n' > /srv/evil/php.ini
sed -e 's#^SEARCH_ROOTS=.*#SEARCH_ROOTS=(/srv/evil)#' $S > /tmp/s.sh
bash /tmp/s.sh --no-restart >/dev/null 2>&1
grep -q upload_progress /srv/evil/php.ini && fail "wrote into world-writable dir" || pass "world-writable dir skipped"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
