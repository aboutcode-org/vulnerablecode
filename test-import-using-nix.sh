#!/usr/bin/env nix-shell
#!nix-shell -i bash

# Populate a test database using either the Nix installation or the local
# checkout.

set -e
DEFAULT_INSTALL_DIR=$VULNERABLECODE_INSTALL_DIR # in the Nix store, see flake.nix
INSTALL_DIR=${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}
ARGS=$(if [ $# -eq 0 ]; then echo "--all"; else echo "$@"; fi)
export DJANGO_DEV=${DJANGO_DEV:-1}

export THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export TEMPDIR=$(mktemp -d -p "$THIS_DIR")
export DATADIR="${TEMPDIR}/pgdata"
export RUNDIR="${TEMPDIR}/run"

cleanup() {
  pg_ctl -D "$DATADIR" stop
  rm -rf "$TEMPDIR"
}

trap cleanup EXIT

ENCODING="UTF-8"
mkdir -p "$RUNDIR"
initdb -D "$DATADIR" -E $ENCODING
pg_ctl -D "$DATADIR" -o "-k $RUNDIR" -l "$DATADIR/logfile" start
createuser --host "$RUNDIR" --no-createrole --no-superuser --login --inherit --createdb vulnerablecode
createdb   --host "$RUNDIR" -E $ENCODING --owner=vulnerablecode --user=vulnerablecode --port=5432 vulnerablecode

"$INSTALL_DIR/manage.py" migrate
"$INSTALL_DIR/manage.py" import $ARGS
