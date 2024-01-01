#!/usr/bin/env bash
set -ex

dns_container_id="$(docker ps | grep "$OVPN_DNS_CONTAINER_NAME_PATTERN" | awk '{ print $1 }' 2> /dev/null)"
if [ "$dns_container_id" != "" ]; then
  echo "Disconnecting network 'vpnet' from $dns_container_id"
  docker network disconnect vpnet "$dns_container_id"
fi
