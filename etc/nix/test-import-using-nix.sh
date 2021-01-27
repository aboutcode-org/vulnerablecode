#!/usr/bin/env nix-shell
#!nix-shell -i bash

# Populate a test database using either the Nix installation or the local
# checkout.

set -e

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
DEFAULT_INSTALL_DIR=$VULNERABLECODE_INSTALL_DIR # in the Nix store, see flake.nix
INSTALL_DIR=${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}
ARGS=$(if [ $# -eq 0 ]; then echo "--all"; else echo "$@"; fi)
export DJANGO_DEV=${DJANGO_DEV:-1}
TEMPDIR=$(mktemp -d -p "$THIS_DIR")
export TEMPDIR

source "$THIS_DIR/lib.sh"

cleanup() {
  pg_ctl -D "$DATADIR" stop
  rm -rf "$TEMPDIR"
}

trap cleanup EXIT

initPostgres "$TEMPDIR"

"$INSTALL_DIR/manage.py" migrate
"$INSTALL_DIR/manage.py" import $ARGS
