#!/usr/bin/env bash
set -euo pipefail

BIN=${BIN:-$PWD/target/release/waffle}
PW=correct-horse-battery
PROXY=http://127.0.0.1:8080
export HOME=$(mktemp -d)
CA=$HOME/.config/waffle/ca.crt
fails=0
HTTP_PID=

cleanup() {
  status=$?
  echo "$PW" | "$BIN" close >/dev/null 2>&1 || true
  [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null || true
  if [ "$status" -ne 0 ] || [ "$fails" -ne 0 ]; then
    echo "--- daemon log ---"
    cat "$HOME/.config/waffle/waffle.log" 2>/dev/null || true
  fi
}
trap cleanup EXIT

code() { curl -q -s -o /dev/null -w '%{http_code}' --max-time 20 -x "$PROXY" "$@" || true; }
body() { curl -q -s --max-time 20 -x "$PROXY" "$@" || true; }

expect() {
  if [ "$2" = "$3" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1: expected $2, got $3"
    fails=$((fails + 1))
  fi
}

wait_for() {
  local want=$1
  shift
  for _ in $(seq 1 40); do
    [ "$(code "$@")" = "$want" ] && return 0
    sleep 0.25
  done
  return 1
}

python3 -m http.server 9000 --bind 127.0.0.1 --directory "$HOME" >/dev/null 2>&1 &
HTTP_PID=$!
sleep 1

printf '%s\n%s\n' "$PW" "$PW" | "$BIN" init
test -s "$CA"
if command -v systemctl >/dev/null; then
  grep -q ExecStart "$HOME/.config/systemd/user/waffle.service"
fi

expect "plain http passes through" 200 "$(code http://127.0.0.1:9000/)"
expect "connect tunnel passes through" 200 "$(code --proxytunnel http://127.0.0.1:9000/)"

for bad in chrome://settings localhost:3000 http://127.0.0.1 ftp://example.com example.com:8080; do
  if echo "$PW" | "$BIN" add "$bad" >/dev/null 2>&1; then
    echo "FAIL accepted $bad"
    fails=$((fails + 1))
  else
    echo "ok   rejected $bad"
  fi
done

if echo wrong | "$BIN" add never.example >/dev/null 2>&1; then
  echo "FAIL wrong password accepted"
  fails=$((fails + 1))
else
  echo "ok   wrong password rejected"
fi

echo "$PW" | "$BIN" add blocked.example pathsite.example/ads
wait_for 403 http://blocked.example/ || echo "reload never took effect"

expect "http blocked" 403 "$(code http://blocked.example/)"
expect "http blocked page" yes "$(body http://blocked.example/ | grep -q Blocked && echo yes || echo no)"
expect "https blocked" 403 "$(code --cacert "$CA" https://blocked.example/)"
expect "https blocked page" yes "$(body --cacert "$CA" https://blocked.example/ | grep -q Blocked && echo yes || echo no)"
expect "www variant blocked" 403 "$(code --cacert "$CA" https://www.blocked.example/)"
expect "other subdomain untouched" 502 "$(code http://sub.blocked.example/)"

expect "https path blocked" 403 "$(code --cacert "$CA" https://pathsite.example/ads/x)"
expect "https other path passes" 502 "$(code --cacert "$CA" https://pathsite.example/ok)"
expect "http path blocked" 403 "$(code http://pathsite.example/ads)"
expect "http other path passes" 502 "$(code http://pathsite.example/ok)"

echo "$PW" | "$BIN" remove blocked.example
wait_for 502 http://blocked.example/ || echo "removal never took effect"
expect "removed site passes" 502 "$(code http://blocked.example/)"

"$BIN" reload

echo "$PW" | "$BIN" close
sleep 1
expect "proxy gone after close" 000 "$(code http://127.0.0.1:9000/)"

[ "$fails" -eq 0 ]
