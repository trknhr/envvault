#!/usr/bin/env sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required; run through envvault exec}"

case "${DATABASE_URL}" in
  postgres://*)
    printf 'DATABASE_URL loaded for app\n'
    ;;
  *)
    printf 'unexpected DATABASE_URL format\n' >&2
    exit 1
    ;;
esac
