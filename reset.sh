#!/usr/bin/env bash
set -eo pipefail

./stop.sh "$@"
./start.sh "$@"
