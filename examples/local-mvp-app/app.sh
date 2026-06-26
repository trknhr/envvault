#!/usr/bin/env sh
set -eu

: "${BACKEND_A_TOKEN:?BACKEND_A_TOKEN is required; run through envvault exec}"

api_base_url="${API_BASE_URL:-http://127.0.0.1:8080}"

curl -sS \
  -H "Authorization: Bearer ${BACKEND_A_TOKEN}" \
  "${api_base_url}/documents/read"
printf '\n'
