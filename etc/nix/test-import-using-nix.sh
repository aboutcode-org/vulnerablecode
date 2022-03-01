#!/usr/bin/env nix-shell
#!nix-shell -i bash

# Populate a test database using either the Nix installation or the local
# checkout.

set -exv

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
DEFAULT_INSTALL_DIR=$VULNERABLECODE_INSTALL_DIR # in the Nix store, see flake.nix
INSTALL_DIR=${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}
ARGS=$(if [ $# -eq 0 ]; then echo "--all"; else echo "$@"; fi)

source "$THIS_DIR/lib.sh"

cleanup() {
  pg_ctl stop
  rm -rf "$TEMPDIR"
}

trap cleanup EXIT

TEMPDIR=$(mktemp -d -p "$THIS_DIR")
cp -r "$INSTALL_DIR" "$TEMPDIR/vulnerablecode"
cd "$TEMPDIR/vulnerablecode"
chmod -R +w .
setupDevEnv

./manage.py migrate
./manage.py collectstatic --no-input
./manage.py import $ARGS
./manage.py improve $ARGS
