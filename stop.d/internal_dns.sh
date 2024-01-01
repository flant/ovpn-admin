#!/usr/bin/env bash
set -exo pipefail

dns_container_id="$(docker ps | grep "$OVPN_DNS_CONTAINER_NAME_PATTERN" | awk '{ print $1 }' 2> /dev/null)"
if [ "$dns_container_id" != "" ]; then
  echo "Disconnecting network 'vpnet' from $dns_container_id"
  docker network disconnect ${OVPN_COMPOSE_NAME}_ovpn-net "$dns_container_id"
fi
