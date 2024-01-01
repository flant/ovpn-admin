#!/usr/bin/env bash
set -exo pipefail

if [ ! -f .env ]; then
    echo "Please create a .env file"
    exit 1
fi

set -a
source .env
set +a

envsubst < ./nginx/default.conf.tpl > ./nginx/default.conf
