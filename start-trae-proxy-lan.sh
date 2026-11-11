#!/usr/bin/env bash
# Compatibility shim: the launcher was renamed to start-trae2api-hub-lan.sh.
# exec keeps the server's lifetime identical to the old script.
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
exec "$HERE/start-trae2api-hub-lan.sh" "$@"
