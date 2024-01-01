#!/usr/bin/env bash
set -eo pipefail

./stop.sh "$@"
./reconfigure.sh
./start.sh "$@"
