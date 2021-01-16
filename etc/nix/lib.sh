#!/usr/bin/env bash

# Setup postgres; see the README for the latest instructions.
#
# $RUNDIR is used to prevent postgres from accessings its default run dir at
# /run/postgresql. See
# https://github.com/NixOS/nixpkgs/issues/83770#issuecomment-607992517
function initPostgres() {
  ROOTDIR=$1
  DATADIR=$ROOTDIR/pgdata
  RUNDIR=$ROOTDIR/run
  ENCODING="UTF-8"
  mkdir -p "$RUNDIR"
  initdb -D "$DATADIR" -E $ENCODING
  pg_ctl -D "$DATADIR" -o "-k $RUNDIR" -l "$DATADIR/logfile" start
  createuser --host "$RUNDIR" --no-createrole --no-superuser --login --inherit --createdb vulnerablecode
  createdb   --host "$RUNDIR" -E $ENCODING --owner=vulnerablecode --user=vulnerablecode --port=5432 vulnerablecode
}
