#!/usr/bin/env bash

# Setup dev environment; see the README for the latest instructions.
setupDevEnv() {
  # Make sure postgres uses a local socket file. The posgres
  # commands (initd,b createdb, createuser, etc.) honor these
  # settings.
  export PGHOST=$PWD
  export PGDATA=./pgdata
  # Start postgres.
  initdb -E utf-8
  pg_ctl -o "-k $PGHOST" -l ./logfile start

  # Setup dev environment.
  export ACTIVATE= # no venv
  sed -i 's/sudo -u postgres//' Makefile # no extra user
  make envfile postgres
}
