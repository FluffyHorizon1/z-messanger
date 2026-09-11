#!/bin/sh
# The log's container starts as root for exactly two chores and then drops
# to the service user for the process itself:
#
#   * a mounted volume or a cloud host's persistent disk arrives owned by
#     root, so the data directory (KT_DATA for the log, KT_MIRROR_DIR for a
#     witness) is handed to z-kt — the directory only; what is in it is
#     already z-kt's;
#   * a seed file mounted read-only from the host is root's, mode 600, so a
#     private copy readable by z-kt is made inside the container and
#     KT_SEED_FILE is pointed at it. The copy lives in the container's own
#     filesystem and goes with it.
#
# If the container is not root (a host that already runs it unprivileged),
# there is nothing to do and the command simply runs.
set -e
if [ "$(id -u)" = "0" ]; then
  for d in "${KT_DATA:-/data}" "${KT_MIRROR_DIR:-}"; do
    if [ -n "$d" ]; then
      mkdir -p "$d"
      chown z-kt "$d"
    fi
  done
  if [ -n "${KT_SEED_FILE:-}" ] && [ -r "$KT_SEED_FILE" ]; then
    cp "$KT_SEED_FILE" /tmp/z-kt.seed
    chown z-kt /tmp/z-kt.seed
    chmod 400 /tmp/z-kt.seed
    export KT_SEED_FILE=/tmp/z-kt.seed
  fi
  exec su-exec z-kt "$@"
fi
exec "$@"
