#!/bin/sh
set -eu
artemis_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$artemis_root/start.sh" --doctor "$@"
