#!/usr/bin/env bash
set -euo pipefail

TARGET_URL=${NUDGPAY_BASE_URL:-http://localhost:8000}
SESSION_COOKIE=""

login() {
  local csrf
  csrf=$(curl -s "${TARGET_URL}/login" | sed -n 's/.*name="_csrf_token" value="\([^"]*\)".*/\1/p')
  SESSION_COOKIE=$(curl -s -c - \
    -d "email=${NUDGPAY_ADMIN_EMAIL:-admin@example.com}" \
    -d "password=${NUDGPAY_ADMIN_PASSWORD:-Password123!}" \
    -d "_csrf_token=${csrf}" \
    "${TARGET_URL}/login" | sed -n 's/.*nudgepay_session\t\(.*\)/nudgepay_session=\1/p')
}

login

zap-baseline.py -t "${TARGET_URL}" -a "" -c nudgepay_zap.conf -z "-config ajaxSpider.browserId=firefox" \
  -s "$SESSION_COOKIE"
