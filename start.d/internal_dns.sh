#!/usr/bin/env bash
set -exo pipefail

dns_container_id="$(docker ps | grep "$OVPN_DNS_CONTAINER_NAME_PATTERN" | awk '{ print $1 }' 2> /dev/null)"
if [ "$dns_container_id" != "" ]; then
  echo "Connecting network 'vpnet' to $dns_container_id"
  docker network connect ${OVPN_COMPOSE_NAME}_ovpn-net "$dns_container_id"
fi
