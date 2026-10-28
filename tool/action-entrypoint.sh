#!/bin/sh
set -eu

# Reports remain private, but must be owned by the workspace user on the host.
if [ "$(id -u)" = 0 ] && [ -d /github/workspace ]; then
    uid=$(stat -c '%u' /github/workspace)
    gid=$(stat -c '%g' /github/workspace)
    if [ "$uid" -ne 0 ]; then
        exec setpriv --reuid "$uid" --regid "$gid" --clear-groups /usr/local/bin/prowl "$@"
    fi
fi
exec /usr/local/bin/prowl "$@"
