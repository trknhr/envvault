#!/usr/bin/env sh
set -eu

: "${OPENAI_BASE_URL:?OPENAI_BASE_URL is required; run through envvault exec}"
: "${OPENAI_API_KEY:?OPENAI_API_KEY is required; run through envvault exec}"

curl -sS \
  -X POST \
  -H "Authorization: Bearer ${OPENAI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model":"demo","messages":[{"role":"user","content":"ping"}]}' \
  "${OPENAI_BASE_URL}/chat/completions"
printf '\n'
