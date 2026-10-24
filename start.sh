#!/bin/sh
set -eu
artemis_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${ARTEMIS_PYTHON:-}" ]; then
    exec "$ARTEMIS_PYTHON" -X utf8 "$artemis_root/launch.py" "$@"
fi
if command -v python3 >/dev/null 2>&1; then
    exec python3 -X utf8 "$artemis_root/launch.py" "$@"
fi
printf '%s\n' 'Python 3.11 or newer was not found. See FIRST_TEST.md.' >&2
exit 2
