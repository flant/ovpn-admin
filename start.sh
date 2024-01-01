#!/usr/bin/env bash
set -eo pipefail

if [ ! -f .env ]; then
    echo "Please create a .env file"
    exit 1
fi

set -a
source .env
set +a

docker-compose -p "$OVPN_COMPOSE_NAME" up -d --force-recreate --always-recreate-deps "$@"

for script_file in ./start.d/*.sh
do
   echo "Sourcing ${script_file}"
   source "${script_file}"
done
