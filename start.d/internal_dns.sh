#!/usr/bin/env bash
set -ex

dns_container_id="$(docker ps | grep "$OVPN_DNS_CONTAINER_NAME_PATTERN" | awk '{ print $1 }' 2> /dev/null)"
if [ "$dns_container_id" != "" ]; then
  echo "Connecting network 'vpnet' to $dns_container_id"
  docker network connect vpnet "$dns_container_id"
fi
