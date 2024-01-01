#!/usr/bin/env bash

if [ ! -f .env ]; then
    echo "Please create a .env file"
    exit 1
fi

source .env

docker compose -p "$OVPN_COMPOSE_NAME" down "$@"

for script_file in ./start.d/*.sh
do
   echo "Sourcing ${script_file}"
   source "${script_file}"
done
